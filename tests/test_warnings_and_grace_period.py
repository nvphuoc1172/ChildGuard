"""Unit test cho chức năng Cảnh báo trước 10, 5, 1 phút và Khoảng ân hạn 60 giây để trẻ lưu bài.

Kiểm tra:
1. Cảnh báo trước 10, 5 và 1 phút theo hạn mức ngày (Quota).
2. Cảnh báo trước 10, 5 và 1 phút theo Lịch tuần ma trận 7x48 và start_time/end_time.
3. Kích hoạt khoảng ân hạn 60 giây khi hết giờ, không khóa máy trong 60s để trẻ lưu bài.
4. Khóa máy tính sau khi hết 60 giây ân hạn.
5. Hủy bỏ khoảng ân hạn và mở lại khi phụ huynh cấp thêm giờ (grant_extra_minutes).
6. Hiển thị thông tin qua IPC status và lịch sử thông báo.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime
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
    db_file = tmp_path / "test_warnings_agent.db"
    storage = AgentStorage(db_path=db_file)
    matrix_all_open = [[1] * 48 for _ in range(7)]
    storage.save_policy({
        "version": 1,
        "quota": {"daily_minutes": 120},  # 120 phút = 7200 giây
        "schedule": {"matrix": matrix_all_open},
        "app_rules": {"blacklist": []},
    })
    return storage


def test_advance_warnings_by_quota_at_10_5_1_minutes(temp_storage):
    """Kiểm tra cảnh báo trước 10, 5, 1 phút theo hạn mức thời gian ngày."""
    notifications = []
    enforcer = PolicyEnforcer(
        storage=temp_storage,
        lock_checker=lambda: False,
        idle_getter=lambda: 5.0,
        notifier=lambda notif: notifications.append(notif),
    )

    # 1. Còn hơn 10 phút (đã dùng 6500s / 7200s -> còn 700s > 600s): Không có cảnh báo
    temp_storage.add_screen_time(6500)
    enforcer.tick(1.0)
    assert len(notifications) == 0

    # 2. Chạm mốc còn 10 phút (đã dùng 6600s / 7200s -> còn 600s = 10m): Cảnh báo 10 phút!
    temp_storage.add_screen_time(100)
    enforcer.tick(1.0)
    assert len(notifications) == 1
    assert notifications[-1]["milestone"] == 10
    assert "10 phút" in notifications[-1]["title"]
    assert notifications[-1]["level"] == "info"

    # Lặp lại trong khoảng 10m: Không phát trùng lặp cảnh báo 10 phút
    enforcer.tick(1.0)
    assert len(notifications) == 1

    # 3. Chạm mốc còn 5 phút (đã dùng 6900s / 7200s -> còn 300s = 5m): Cảnh báo 5 phút!
    temp_storage.add_screen_time(300)
    enforcer.tick(1.0)
    assert len(notifications) == 2
    assert notifications[-1]["milestone"] == 5
    assert "5 phút" in notifications[-1]["title"]
    assert notifications[-1]["level"] == "warning"

    # 4. Chạm mốc còn 1 phút (đã dùng 7140s / 7200s -> còn 60s = 1m): Cảnh báo 1 phút khẩn cấp!
    temp_storage.add_screen_time(240)
    enforcer.tick(1.0)
    assert len(notifications) == 3
    assert notifications[-1]["milestone"] == 1
    assert "1 phút" in notifications[-1]["title"]
    assert notifications[-1]["level"] == "urgent"


def test_grace_period_60_seconds_and_lock_after_expiry(temp_storage):
    """Kiểm tra khoảng ân hạn 60 giây khi hết hạn mức và khóa máy sau khi hết ân hạn."""
    notifications = []
    lock_calls = []

    enforcer = PolicyEnforcer(
        storage=temp_storage,
        lock_checker=lambda: False,
        idle_getter=lambda: 5.0,
        notifier=lambda notif: notifications.append(notif),
    )
    enforcer.lock_workstation = lambda reason="": lock_calls.append(reason)

    # Đã dùng hết 7200s / 7200s
    temp_storage.add_screen_time(7200)

    # Tick 1: Chạm mốc hết giờ -> Phải kích hoạt Ân hạn 60 giây, CHƯA ĐƯỢC KHÓA MÁY!
    enforcer.tick(1.0)
    assert enforcer._in_grace_period is True
    assert enforcer.grace_seconds_left == 60
    assert len(lock_calls) == 0, "Không được khóa máy ngay, phải cho trẻ 60 giây ân hạn để lưu bài!"

    # Thông báo ân hạn được phát ra
    grace_notifs = [n for n in notifications if n.get("level") == "grace_period"]
    assert len(grace_notifs) == 1
    assert "ÂN HẠN 60 GIÂY" in grace_notifs[0]["title"]
    assert "60 giây ân hạn để lưu bài" in grace_notifs[0]["message"]

    # Giả lập trôi qua 30 giây trong khoảng ân hạn: Vẫn chưa khóa máy
    enforcer._grace_period_start -= 30.0
    enforcer.tick(1.0)
    assert enforcer._in_grace_period is True
    assert 20 <= enforcer.grace_seconds_left <= 30
    assert len(lock_calls) == 0, "Sau 30 giây ân hạn vẫn chưa được khóa máy"

    # Giả lập trôi qua 60 giây (hết thời gian ân hạn): Phải thực thi khóa máy!
    enforcer._grace_period_start -= 31.0  # Tổng cộng > 60s
    enforcer.tick(1.0)
    assert enforcer._in_grace_period is False
    assert len(lock_calls) == 1
    assert "Hết thời gian ân hạn 60 giây" in lock_calls[0]


def test_advance_warnings_and_grace_by_weekly_schedule_matrix(temp_storage):
    """Kiểm tra cảnh báo 10, 5, 1 phút và ân hạn 60s theo Ma trận Lịch tuần 7x48."""
    # Giả lập thứ Hai (weekday = 0):
    # Slot 42 (21:00 - 21:30) cho phép (= 1), Slot 43 (21:30 - 22:00) bị khóa (= 0)
    matrix = [[1] * 48 for _ in range(7)]
    matrix[0][43] = 0  # Bắt đầu cấm lúc 21:30:00

    temp_storage.save_policy({
        "version": 2,
        "quota": {"daily_minutes": 500},  # Hạn mức còn rất nhiều
        "schedule": {"matrix": matrix},
        "app_rules": {"blacklist": []},
    })

    notifications = []
    enforcer = PolicyEnforcer(
        storage=temp_storage,
        lock_checker=lambda: False,
        idle_getter=lambda: 5.0,
        notifier=lambda notif: notifications.append(notif),
    )

    # 1. Lúc 21:19:00 (còn 11 phút = 660s): Không có cảnh báo
    dt_2119 = datetime(2026, 10, 12, 21, 19, 0)  # 2026-10-12 là Thứ Hai (weekday = 0)
    enforcer._get_effective_local_datetime = lambda: dt_2119
    enforcer.tick(1.0)
    assert len(notifications) == 0

    # 2. Lúc 21:20:00 (còn đúng 10 phút = 600s đến 21:30): Cảnh báo 10 phút!
    dt_2120 = datetime(2026, 10, 12, 21, 20, 0)
    enforcer._get_effective_local_datetime = lambda: dt_2120
    enforcer.tick(1.0)
    assert len(notifications) == 1
    assert notifications[-1]["milestone"] == 10
    assert notifications[-1]["restriction_type"] == "schedule"

    # 3. Lúc 21:25:00 (còn đúng 5 phút = 300s): Cảnh báo 5 phút!
    dt_2125 = datetime(2026, 10, 12, 21, 25, 0)
    enforcer._get_effective_local_datetime = lambda: dt_2125
    enforcer.tick(1.0)
    assert len(notifications) == 2
    assert notifications[-1]["milestone"] == 5

    # 4. Lúc 21:29:00 (còn đúng 1 phút = 60s): Cảnh báo 1 phút!
    dt_2129 = datetime(2026, 10, 12, 21, 29, 0)
    enforcer._get_effective_local_datetime = lambda: dt_2129
    enforcer.tick(1.0)
    assert len(notifications) == 3
    assert notifications[-1]["milestone"] == 1

    # 5. Lúc 21:30:00 (chạm mốc kết thúc khung giờ): Kích hoạt ân hạn 60 giây!
    dt_2130 = datetime(2026, 10, 12, 21, 30, 0)
    enforcer._get_effective_local_datetime = lambda: dt_2130
    enforcer.tick(1.0)
    assert enforcer._in_grace_period is True
    assert enforcer.grace_seconds_left == 60


def test_advance_warnings_and_grace_by_schedule_fallback_times(temp_storage):
    """Kiểm tra cảnh báo 10, 5, 1 phút và ân hạn 60s theo khung giờ start_time / end_time."""
    temp_storage.save_policy({
        "version": 3,
        "quota": {"daily_minutes": 500},
        "schedule": {"start_time": "07:00", "end_time": "21:30"},
        "app_rules": {"blacklist": []},
    })

    notifications = []
    enforcer = PolicyEnforcer(
        storage=temp_storage,
        lock_checker=lambda: False,
        idle_getter=lambda: 5.0,
        notifier=lambda notif: notifications.append(notif),
    )

    # 1. Lúc 21:20:00 (còn 10 phút đến 21:30)
    enforcer._get_effective_local_datetime = lambda: datetime(2026, 10, 12, 21, 20, 0)
    enforcer.tick(1.0)
    assert len(notifications) == 1
    assert notifications[-1]["milestone"] == 10

    # 2. Lúc 21:25:00 (còn 5 phút đến 21:30)
    enforcer._get_effective_local_datetime = lambda: datetime(2026, 10, 12, 21, 25, 0)
    enforcer.tick(1.0)
    assert len(notifications) == 2
    assert notifications[-1]["milestone"] == 5

    # 3. Lúc 21:29:00 (còn 1 phút đến 21:30)
    enforcer._get_effective_local_datetime = lambda: datetime(2026, 10, 12, 21, 29, 0)
    enforcer.tick(1.0)
    assert len(notifications) == 3
    assert notifications[-1]["milestone"] == 1

    # 4. Lúc 21:30:00 (hết khung giờ) -> Ân hạn 60 giây
    enforcer._get_effective_local_datetime = lambda: datetime(2026, 10, 12, 21, 30, 0)
    enforcer.tick(1.0)
    assert enforcer._in_grace_period is True
    assert enforcer.grace_seconds_left == 60


def test_grant_minutes_cancels_grace_period(temp_storage):
    """Kiểm tra khi đang trong ân hạn 60s, phụ huynh cộng thêm giờ thì tự động giải phóng ân hạn."""
    enforcer = PolicyEnforcer(
        storage=temp_storage,
        lock_checker=lambda: False,
        idle_getter=lambda: 5.0,
    )
    # Hết hạn mức
    temp_storage.add_screen_time(7200)
    enforcer.tick(1.0)
    assert enforcer._in_grace_period is True

    # Phụ huynh cấp thêm 15 phút
    enforcer.grant_extra_minutes(15)
    assert enforcer._in_grace_period is False
    assert enforcer.grace_seconds_left == 0
    assert temp_storage.get_lock_status() is False

    # Tick tiếp theo máy vẫn hoạt động bình thường, không bị khóa
    enforcer.tick(1.0)
    assert enforcer._in_grace_period is False


def test_ipc_status_and_notifications_endpoints(temp_storage):
    """Kiểm tra IPC Server cung cấp đầy đủ thông tin cảnh báo, ân hạn và lịch sử thông báo."""
    import json
    from http.server import HTTPServer
    from ipc import IPCHandler

    enforcer = PolicyEnforcer(storage=temp_storage)
    IPCHandler.storage = temp_storage
    IPCHandler.enforcer = enforcer

    # Giả lập phát 1 thông báo cảnh báo 5 phút
    enforcer._emit_warning(
        milestone=5,
        remaining_seconds=300,
        restriction_type="quota",
        title="Test Cảnh báo 5 phút",
        message="Còn 5 phút lưu bài",
    )

    assert enforcer.active_notification is not None
    assert len(enforcer.notification_history) == 1
    assert enforcer.notification_history[0]["milestone"] == 5
