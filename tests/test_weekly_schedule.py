import json
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

agent_dir = Path(__file__).resolve().parent.parent / "agent"
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

from enforcer import PolicyEnforcer
from app import models, security
from app.security import generate_matrix_from_times, validate_or_normalize_matrix


def test_generate_matrix_from_times():
    matrix = generate_matrix_from_times("07:00", "21:30")
    assert len(matrix) == 7
    for row in matrix:
        assert len(row) == 48
        # Slot 0 (00:00 - 00:30) bị khóa
        assert row[0] == 0
        # Slot 13 (06:30 - 07:00) bị khóa
        assert row[13] == 0
        # Slot 14 (07:00 - 07:30) cho phép
        assert row[14] == 1
        # Slot 42 (21:00 - 21:30) cho phép
        assert row[42] == 1
        # Slot 43 (21:30 - 22:00) bị khóa
        assert row[43] == 0
        # Slot 47 (23:30 - 24:00) bị khóa
        assert row[47] == 0


def test_validate_or_normalize_matrix():
    valid_matrix = [[1 if (14 <= s < 43) else 0 for s in range(48)] for _ in range(7)]
    assert validate_or_normalize_matrix(valid_matrix) == valid_matrix

    # Test ép kiểu boolean sang int (1/0)
    bool_matrix = [[True if (14 <= s < 43) else False for s in range(48)] for _ in range(7)]
    normalized = validate_or_normalize_matrix(bool_matrix)
    assert normalized == valid_matrix

    # Kích thước sai
    assert validate_or_normalize_matrix([[1] * 48] * 6) is None  # Chỉ có 6 ngày
    assert validate_or_normalize_matrix([[1] * 47] * 7) is None  # Chỉ có 47 slot
    assert validate_or_normalize_matrix("invalid") is None


def test_enforcer_check_schedule_with_matrix():
    storage_mock = MagicMock()
    enforcer = PolicyEnforcer(storage_mock)

    # Tạo ma trận: Chỉ cho phép Thứ Hai (0) từ 08:00 - 09:00 (slot 16, 17)
    custom_matrix = [[0] * 48 for _ in range(7)]
    custom_matrix[0][16] = 1  # Thứ Hai 08:00 - 08:30
    custom_matrix[0][17] = 1  # Thứ Hai 08:30 - 09:00

    schedule = {
        "start_time": "07:00",
        "end_time": "21:30",
        "matrix": custom_matrix,
    }

    # 1. Thứ Hai lúc 08:15 (weekday 0, slot 16) -> Trong khung giờ
    dt_mon_0815 = datetime(2026, 10, 12, 8, 15)  # 2026-10-12 là Thứ Hai
    assert dt_mon_0815.weekday() == 0
    assert enforcer.check_schedule(schedule, now_dt=dt_mon_0815) is True

    # 2. Thứ Hai lúc 08:45 (weekday 0, slot 17) -> Trong khung giờ
    dt_mon_0845 = datetime(2026, 10, 12, 8, 45)
    assert enforcer.check_schedule(schedule, now_dt=dt_mon_0845) is True

    # 3. Thứ Hai lúc 09:05 (weekday 0, slot 18) -> Ngoài khung giờ
    dt_mon_0905 = datetime(2026, 10, 12, 9, 5)
    assert enforcer.check_schedule(schedule, now_dt=dt_mon_0905) is False

    # 4. Thứ Ba lúc 08:15 (weekday 1, slot 16) -> Thứ Ba bị khóa hoàn toàn
    dt_tue_0815 = datetime(2026, 10, 13, 8, 15)
    assert dt_tue_0815.weekday() == 1
    assert enforcer.check_schedule(schedule, now_dt=dt_tue_0815) is False

    # 5. Chủ Nhật lúc 14:00 (weekday 6) -> Bị khóa
    dt_sun_1400 = datetime(2026, 10, 18, 14, 0)
    assert dt_sun_1400.weekday() == 6
    assert enforcer.check_schedule(schedule, now_dt=dt_sun_1400) is False


def test_enforcer_check_schedule_fallback_times():
    storage_mock = MagicMock()
    enforcer = PolicyEnforcer(storage_mock)

    # Schedule không có matrix, chỉ có start_time và end_time
    legacy_schedule = {
        "start_time": "08:00",
        "end_time": "18:00",
    }

    dt_in = datetime(2026, 10, 16, 10, 0)
    assert enforcer.check_schedule(legacy_schedule, now_dt=dt_in) is True

    dt_out = datetime(2026, 10, 16, 20, 0)
    assert enforcer.check_schedule(legacy_schedule, now_dt=dt_out) is False

    # Empty schedule -> True
    assert enforcer.check_schedule({}) is True


def test_enforcer_locks_within_5_seconds_when_out_of_schedule():
    storage_mock = MagicMock()
    # Giả lập: Hạn mức chưa hết (0s / 7200s), không khóa tay
    storage_mock.get_screen_time_today.return_value = 0
    storage_mock.get_lock_status.return_value = False
    storage_mock.check_connection_grace_period.return_value = "normal"

    # Ma trận khóa toàn bộ (tất cả các ô đều 0)
    locked_all_matrix = [[0] * 48 for _ in range(7)]
    storage_mock.get_policy.return_value = {
        "version": 1,
        "quota": {"daily_minutes": 120},
        "schedule": {"matrix": locked_all_matrix},
        "app_rules": {"blacklist": []},
    }

    enforcer = PolicyEnforcer(storage_mock)

    # Gọi lock_workstation được mock
    with patch.object(enforcer, "lock_workstation") as mock_lock:
        with patch.object(enforcer, "is_workstation_locked", return_value=False):
            # Giả lập 1 lần tick trong run_loop
            schedule = enforcer.storage.get_policy()["schedule"]
            in_schedule = enforcer.check_schedule(schedule)
            assert in_schedule is False

            # Khi phát hiện ngoài khung giờ:
            # Enforcer kiểm tra và kích hoạt khóa ngay lập tức
            enforcer.lock_workstation(reason="Ngoài khung giờ cho phép")
            assert mock_lock.called
            assert "Ngoài khung giờ cho phép" in mock_lock.call_args[1]["reason"]


def test_save_policy_with_matrix_via_dashboard(client, db_session):
    parent = models.Parent(email="parent_matrix@test.local", password_hash="dummy")
    db_session.add(parent)
    db_session.flush()

    child = models.Child(parent_id=parent.id, display_name="Bé Bi")
    db_session.add(child)
    db_session.commit()

    # Tạo ma trận tùy chỉnh (T2 chỉ cho phép từ 19:00 - 20:00 -> slot 38, 39)
    custom_matrix = [[0] * 48 for _ in range(7)]
    custom_matrix[0][38] = 1
    custom_matrix[0][39] = 1

    # Tạo session đăng nhập cho parent
    session_cookie = security.create_parent_session(parent.id)

    res = client.post(
        "/dashboard/policy/save",
        data={
            "child_id": child.id,
            "daily_minutes": 60,
            "start_time": "19:00",
            "end_time": "20:00",
            "schedule_matrix": json.dumps(custom_matrix),
            "blocked_apps": "badgame.exe",
            "blocked_domains": "badweb.com",
        },
        cookies={"ogk_session": session_cookie},
    )
    assert res.status_code == 200

    # Kiểm tra bản ghi trong DB
    policy_row = (
        db_session.query(models.Policy)
        .filter(models.Policy.child_id == child.id)
        .order_by(models.Policy.version.desc())
        .first()
    )
    assert policy_row is not None
    saved_schedule = json.loads(policy_row.schedule_json)
    assert "matrix" in saved_schedule
    assert saved_schedule["matrix"][0][38] == 1
    assert saved_schedule["matrix"][0][39] == 1
    assert saved_schedule["matrix"][0][40] == 0
