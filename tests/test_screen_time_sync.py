"""Unit test cho chức năng đếm thời gian sử dụng thực và đồng bộ thời gian UTC.

Kiểm tra:
1. Đếm thời gian sử dụng thực: sai số <= +-30 giây trên mỗi giờ so với đồng hồ bấm tay (thực tế <= +-1s).
2. Không tính thời gian khi máy khóa (workstation locked).
3. Không tính thời gian khi không có thao tác quá 5 phút (idle >= 300s) và tự động tiếp tục khi hoạt động trở lại.
4. Đồng bộ thời gian Server - Client:
   - Heartbeat trả về server_time và server_timestamp.
   - Storage đồng bộ thời gian và chống tua ngược đồng hồ RTC bằng monotonic clock.
   - Ngày tính quota sử dụng ngày UTC đồng bộ, triệt tiêu lỗi lệch múi giờ GMT.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

agent_dir = Path(__file__).resolve().parent.parent / "agent"
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

from enforcer import PolicyEnforcer
from storage import AgentStorage


@pytest.fixture
def temp_storage(tmp_path):
    db_file = tmp_path / "test_agent.db"
    storage = AgentStorage(db_path=db_file)
    # Cài đặt policy mặc định cho phép cả ngày
    matrix_all_open = [[1] * 48 for _ in range(7)]
    storage.save_policy({
        "version": 1,
        "quota": {"daily_minutes": 180},
        "schedule": {"matrix": matrix_all_open},
        "app_rules": {"blacklist": []},
    })
    return storage


def test_agent_event_diagnostics_retain_server_ack(temp_storage):
    event_key = temp_storage.add_event("blocked_domain", subject="sub.example.com")
    pending = temp_storage.get_pending_events()
    assert len(pending) == 1
    temp_storage.mark_events_sent([pending[0]["id"]])

    assert temp_storage.get_pending_events() == []
    recent = temp_storage.get_recent_events()
    assert recent[0]["idempotency_key"] == event_key
    assert recent[0]["type"] == "blocked_domain"
    assert recent[0]["subject"] == "example.com"
    assert recent[0]["status"] == "sent"


def test_repairing_device_isolates_old_child_data(temp_storage):
    assert temp_storage.bind_device("device-old") is True
    temp_storage.save_policy({"version": 9, "app_rules": {"blacklist": ["game.exe"]}})
    temp_storage.add_event("app_start", subject="study.exe")

    assert temp_storage.bind_device("device-old") is False
    assert len(temp_storage.get_pending_events()) == 1

    assert temp_storage.bind_device("device-new") is True
    assert temp_storage.get_pending_events() == []
    assert temp_storage.get_recent_events() == []
    assert temp_storage.get_policy()["version"] == 0


def test_monotonic_screen_time_precision_within_30s_per_hour(temp_storage):
    """Kiểm tra độ chính xác: Sai số tích lũy sau 1 giờ (3600s) <= +-30s (chuẩn yêu cầu)."""
    enforcer = PolicyEnforcer(
        storage=temp_storage,
        lock_checker=lambda: False,
        idle_getter=lambda: 10.0,  # Đang hoạt động tích cực
    )

    # Giả lập 1800 vòng lặp tick, mỗi tick dao động thực tế từ 1.95s đến 2.05s
    # Tổng thời gian thực tế = đúng 3600.00 giây (1 giờ đồng hồ bấm tay)
    ticks = []
    accumulated_sim_time = 0.0
    for i in range(1799):
        # Xen kẽ 2.02s và 1.98s
        dt = 2.02 if i % 2 == 0 else 1.98
        ticks.append(dt)
        accumulated_sim_time += dt

    # Tick cuối cùng bù chuẩn xác để tổng tròn 3600.0s
    last_dt = round(3600.0 - accumulated_sim_time, 4)
    ticks.append(last_dt)
    assert abs(sum(ticks) - 3600.0) < 1e-6

    # Chạy mô phỏng qua tick()
    for dt in ticks:
        enforcer.tick(dt)

    recorded_used_sec = temp_storage.get_screen_time_today()
    diff = abs(recorded_used_sec - 3600)

    print(f"\n[Test Precision] Tổng thời gian thực tế: 3600s, Đã ghi nhận: {recorded_used_sec}s, Sai số: {diff}s")
    # Sai số yêu cầu là <= 30 giây. Giải pháp sub-second buffer đạt sai số <= 1 giây!
    assert diff <= 30, f"Sai số {diff}s vượt quá giới hạn +-30s/giờ!"
    assert diff <= 1, f"Kỳ vọng thuật toán subsecond buffer đạt sai số <= 1s, nhưng thực tế là {diff}s"


def test_screen_time_not_counted_when_workstation_locked(temp_storage):
    """Kiểm tra: không tính thời gian khi máy khóa."""
    is_locked = False

    def dynamic_lock_checker():
        return is_locked

    enforcer = PolicyEnforcer(
        storage=temp_storage,
        lock_checker=dynamic_lock_checker,
        idle_getter=lambda: 5.0,
    )

    # 1. Máy đang mở, hoạt động trong 10 giây
    for _ in range(5):
        enforcer.tick(2.0)
    assert temp_storage.get_screen_time_today() == 10

    # 2. Khóa máy màn hình Lock Screen
    is_locked = True
    for _ in range(10):  # Trôi qua 20 giây khi máy khóa
        enforcer.tick(2.0)

    # Thời gian sử dụng PHẢI giữ nguyên 10 giây, không được tăng
    assert temp_storage.get_screen_time_today() == 10

    # 3. Mở khóa máy lại, dùng thêm 6 giây
    is_locked = False
    for _ in range(3):
        enforcer.tick(2.0)

    # Thời gian tăng lên 16 giây
    assert temp_storage.get_screen_time_today() == 16


def test_screen_time_not_counted_when_idle_over_5_minutes(temp_storage):
    """Kiểm tra: không tính thời gian khi không có thao tác quá 5 phút (>= 300s)."""
    current_idle = 10.0

    def dynamic_idle_getter():
        return current_idle

    enforcer = PolicyEnforcer(
        storage=temp_storage,
        lock_checker=lambda: False,
        idle_getter=dynamic_idle_getter,
    )

    # 1. Thao tác bình thường (idle = 10s < 300s): đếm thời gian
    enforcer.tick(4.0)
    assert temp_storage.get_screen_time_today() == 4
    assert enforcer.is_idle is False

    # 2. Người dùng rời máy, không có thao tác: idle chạm ngưỡng và vượt 300 giây (5 phút)
    current_idle = 300.0  # Vừa đúng 5 phút
    enforcer.tick(2.0)
    assert enforcer.is_idle is True
    # Không được cộng thời gian trong chu kỳ này
    assert temp_storage.get_screen_time_today() == 4

    # Tiếp tục không thao tác (idle = 450s > 300s)
    current_idle = 450.0
    for _ in range(5):
        enforcer.tick(2.0)
    assert enforcer.is_idle is True
    assert temp_storage.get_screen_time_today() == 4

    # 3. Người dùng quay lại máy, gõ phím/rê chuột -> idle trở lại 0.5s (< 300s)
    current_idle = 0.5
    enforcer.tick(3.0)
    assert enforcer.is_idle is False
    # Thời gian đếm tiếp tục từ mốc cũ (4 + 3 = 7s)
    assert temp_storage.get_screen_time_today() == 7


def test_server_time_sync_and_rtc_tamper_protection(temp_storage):
    """Kiểm tra đồng bộ thời gian UTC với Server và chống tua ngược RTC."""
    # Giả lập Server đang ở 2026-10-16 12:00:00 UTC
    server_utc_ts = 1792152000.0  # epoch timestamp chuẩn từ server
    temp_storage.sync_server_time(server_utc_ts)

    # Kiểm tra timestamp đồng bộ
    synced_ts = temp_storage.get_server_utc_timestamp()
    assert abs(synced_ts - server_utc_ts) < 0.5

    # Kiểm tra ngày UTC đã đồng bộ
    utc_date = temp_storage.get_current_utc_date_str()
    synced_dt = temp_storage.get_server_utc_datetime()
    assert synced_dt.strftime("%Y-%m-%d") == utc_date

    # Giả lập hành vi tua ngược đồng hồ RTC trên máy Client
    with patch("time.time", return_value=1000000.0):
        # Mặc dù time.time() bị tua ngược về quá khứ xa,
        # get_server_utc_timestamp() dùng mốc monotonic nên không bị ảnh hưởng!
        tampered_ts = temp_storage.get_server_utc_timestamp()
        assert abs(tampered_ts - server_utc_ts) < 2.0


def test_heartbeat_syncs_server_time_and_date(client, db_session, temp_storage):
    """Kiểm tra endpoint /heartbeat trả về server_time, server_timestamp và đồng bộ thành công vào client."""
    from datetime import timedelta
    from app import models

    parent = models.Parent(email="sync_test@test.local", password_hash="dummy")
    db_session.add(parent)
    db_session.flush()

    child = models.Child(parent_id=parent.id, display_name="Test Child")
    db_session.add(child)
    db_session.flush()

    code = "SYNCTEST"
    enrollment = models.EnrollmentCode(
        code=code,
        parent_id=parent.id,
        child_id=child.id,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db_session.add(enrollment)
    db_session.commit()

    resp_enroll = client.post("/enroll", json={"code": code, "device_fingerprint": "a" * 64})
    assert resp_enroll.status_code == 201
    token_str = resp_enroll.json()["access_token"]

    # Gửi heartbeat từ client lên server
    resp = client.post(
        "/heartbeat",
        json={"policy_version": 1, "quota_used_seconds": 120, "queued_event_count": 0},
        headers={"Authorization": f"Bearer {token_str}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert "server_time" in data and data["server_time"] is not None
    assert "server_timestamp" in data and data["server_timestamp"] is not None

    # SyncWorker nhận response và gọi sync_server_time
    temp_storage.sync_server_time(data["server_timestamp"])
    synced_ts = temp_storage.get_server_utc_timestamp()
    assert abs(synced_ts - data["server_timestamp"]) < 1.0
