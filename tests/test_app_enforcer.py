import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

agent_dir = Path(__file__).resolve().parent.parent / "agent"
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

from enforcer import (
    ESSENTIAL_SYSTEM_PROCESSES,
    PolicyEnforcer,
    check_process_rule,
    get_file_sha256,
    parse_app_rule_entry,
)
from app import models, security


def test_get_file_sha256_and_cache():
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"Hello ChildGuard Anti-Cheat")
        f.flush()
        f_path = f.name

    try:
        expected_hash = hashlib.sha256(b"Hello ChildGuard Anti-Cheat").hexdigest().lower()
        computed_hash = get_file_sha256(f_path)
        assert computed_hash == expected_hash

        # Kiểm tra đọc từ cache
        cached_hash = get_file_sha256(f_path)
        assert cached_hash == expected_hash

        # File không tồn tại
        assert get_file_sha256("/non_existent_file_path_123456.exe") is None
    finally:
        if os.path.exists(f_path):
            os.remove(f_path)


def test_parse_app_rule_entry():
    # 1. Tên tiến trình đơn thuần
    r1 = parse_app_rule_entry("game.exe")
    assert r1 == {"name": "game.exe", "sha256": None}

    # 2. Tên tiến trình kèm hash (dấu hai chấm)
    dummy_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    r2 = parse_app_rule_entry(f"game.exe:{dummy_hash}")
    assert r2 == {"name": "game.exe", "sha256": dummy_hash}

    # 3. Đường dẫn Windows kèm hash (C:\Games\game.exe:hash)
    r3 = parse_app_rule_entry(rf"C:\Games\SubFolder\game.exe:{dummy_hash}")
    assert r3 == {"name": "game.exe", "sha256": dummy_hash}

    # 4. Tên tiến trình kèm hash (khoảng trắng)
    r4 = parse_app_rule_entry(f"notepad.exe {dummy_hash}")
    assert r4 == {"name": "notepad.exe", "sha256": dummy_hash}

    # 5. Chỉ có mã hash 64 ký tự hex
    r5 = parse_app_rule_entry(dummy_hash)
    assert r5 == {"name": None, "sha256": dummy_hash}

    # 6. Dạng dictionary
    r6 = parse_app_rule_entry({"name": "roblox.exe", "sha256": dummy_hash})
    assert r6 == {"name": "roblox.exe", "sha256": dummy_hash}


def test_essential_system_processes_never_blocked():
    # Các tiến trình hệ thống như svchost.exe, explorer.exe, python.exe không bao giờ bị terminate
    for proc in ["explorer.exe", "svchost.exe", "python.exe", "csrss.exe"]:
        # Trong blacklist
        is_blocked, reason, _ = check_process_rule(
            proc_name=proc,
            proc_sha256=None,
            app_rules={"mode": "blacklist", "blacklist": [proc]},
        )
        assert is_blocked is False

        # Trong whitelist (dù không có tên trong whitelist)
        is_blocked, reason, _ = check_process_rule(
            proc_name=proc,
            proc_sha256=None,
            app_rules={"mode": "whitelist", "whitelist": ["notepad.exe"]},
        )
        assert is_blocked is False


def test_renamed_notepad_to_game_not_blocked_in_blacklist():
    """Yêu cầu cốt lõi: Đổi tên notepad.exe thành game.exe vẫn bị nhận diện đúng là Notepad và không bị chặn oan."""
    notepad_hash = "aaaa1111222233334444555566667777888899990000aaaabbbbccccddddeeee"
    game_hash = "ffff1111222233334444555566667777888899990000ffffbbbbccccddddeeee"

    known_hashes = {"notepad.exe": notepad_hash}
    app_rules = {
        "mode": "blacklist",
        "blacklist": ["game.exe", f"badapp.exe:{game_hash}"],
    }

    # Trẻ đổi tên notepad.exe thành game.exe:
    # Tên tiến trình là 'game.exe', nhưng SHA-256 là của notepad.exe!
    is_blocked, reason, identified = check_process_rule(
        proc_name="game.exe",
        proc_sha256=notepad_hash,
        app_rules=app_rules,
        known_system_hashes=known_hashes,
    )

    # Hệ thống phải nhận diện đúng đây là notepad.exe và KHÔNG được chặn!
    assert is_blocked is False
    assert identified == "notepad.exe"


def test_renamed_game_to_notepad_is_blocked_in_blacklist():
    """Ngược lại: Trẻ đổi tên game cấm thành notepad.exe vẫn bị nhận diện đúng mã băm và bị chặn."""
    notepad_hash = "aaaa1111222233334444555566667777888899990000aaaabbbbccccddddeeee"
    game_hash = "ffff1111222233334444555566667777888899990000ffffbbbbccccddddeeee"

    known_hashes = {"notepad.exe": notepad_hash, "game.exe": game_hash}
    app_rules = {
        "mode": "blacklist",
        "blacklist": [f"game.exe:{game_hash}"],
    }

    # Tên tiến trình là 'notepad.exe', nhưng SHA-256 là của game bị cấm!
    is_blocked, reason, identified = check_process_rule(
        proc_name="notepad.exe",
        proc_sha256=game_hash,
        app_rules=app_rules,
        known_system_hashes=known_hashes,
    )

    # Phải bị chặn!
    assert is_blocked is True
    assert identified == "game.exe"


def test_whitelist_mode_with_identity_resolution():
    """Kiểm tra chế độ Whitelist (Danh sách trắng)."""
    notepad_hash = "aaaa1111222233334444555566667777888899990000aaaabbbbccccddddeeee"
    known_hashes = {"notepad.exe": notepad_hash}

    # Whitelist chỉ cho phép notepad.exe
    app_rules = {
        "mode": "whitelist",
        "whitelist": ["notepad.exe"],
    }

    # 1. Ứng dụng notepad.exe chuẩn -> Được phép
    is_blocked, _, identified = check_process_rule("notepad.exe", notepad_hash, app_rules, known_hashes)
    assert is_blocked is False
    assert identified == "notepad.exe"

    # 2. notepad.exe đổi tên thành game.exe nhưng hash là của notepad.exe -> Được phép vì nhận diện đúng là notepad!
    is_blocked, _, identified = check_process_rule("game.exe", notepad_hash, app_rules, known_hashes)
    assert is_blocked is False
    assert identified == "notepad.exe"

    # 3. Game lạ đổi tên thành notepad.exe nhưng hash không phải notepad.exe -> Bị chặn vì giả mạo tên
    fake_hash = "1111222233334444555566667777888899990000111122223333444455556666"
    is_blocked, _, _ = check_process_rule("notepad.exe", fake_hash, app_rules, known_hashes)
    assert is_blocked is True

    # 4. Ứng dụng khác không có trong whitelist (ví dụ: roblox.exe) -> Bị chặn
    is_blocked, _, _ = check_process_rule("roblox.exe", fake_hash, app_rules, known_hashes)
    assert is_blocked is True


def test_scan_and_enforce_processes_mocked(tmp_path):
    """Kiểm tra hoạt động quét và terminate của PolicyEnforcer khi có tiến trình bị đổi tên."""
    notepad_hash = "aaaa1111222233334444555566667777888899990000aaaabbbbccccddddeeee"
    game_hash = "ffff1111222233334444555566667777888899990000ffffbbbbccccddddeeee"

    mock_storage = MagicMock()
    enforcer = PolicyEnforcer(
        storage=mock_storage,
        known_system_hashes={"notepad.exe": notepad_hash, "game.exe": game_hash},
    )

    policy = {
        "version": 2,
        "app_rules": {
            "mode": "blacklist",
            "blacklist": [f"game.exe:{game_hash}"],
        },
    }

    # Tạo mock các tiến trình:
    # Proc 1: notepad.exe bị đổi tên thành game.exe (hash notepad) -> KHÔNG ĐƯỢC TERMINATE
    proc_renamed_notepad = MagicMock()
    proc_renamed_notepad.info = {"pid": 1001, "name": "game.exe", "exe": "/bin/notepad"}
    proc_renamed_notepad.kill = MagicMock()

    # Proc 2: game.exe đổi tên thành notepad.exe (hash game) -> PHẢI TERMINATE
    proc_renamed_game = MagicMock()
    proc_renamed_game.info = {"pid": 1002, "name": "notepad.exe", "exe": "/bin/game"}
    proc_renamed_game.kill = MagicMock()

    def mock_get_hash(path):
        if path == "/bin/notepad":
            return notepad_hash
        if path == "/bin/game":
            return game_hash
        return None

    with patch("enforcer.get_file_sha256", side_effect=mock_get_hash):
        with patch("enforcer.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc_renamed_notepad, proc_renamed_game]

            enforcer.scan_and_enforce_processes(policy)

            # Proc 1 không bị kill
            proc_renamed_notepad.kill.assert_not_called()

            # Proc 2 bị kill và ghi event
            proc_renamed_game.kill.assert_called_once()
            event_calls = mock_storage.add_event.call_args_list
            # Lần quét đầu là baseline nên không phát app_start cho các process
            # đã chạy trước Agent; sự kiện chặn thực tế vẫn phải được ghi ngay.
            assert [call.kwargs["type"] for call in event_calls] == ["blocked_app"]
            assert event_calls[-1].kwargs["subject"] == "notepad.exe"


def test_dashboard_save_policy_with_app_mode(client, db_session):
    """Kiểm tra lưu chính sách với app_mode (whitelist và blacklist) từ Dashboard."""
    parent = models.Parent(email="parent_app_mode@test.local", password_hash="dummy")
    db_session.add(parent)
    db_session.flush()

    child = models.Child(parent_id=parent.id, display_name="Bé Thảo")
    db_session.add(child)
    db_session.commit()

    session_cookie = security.create_parent_session(parent.id)
    client.cookies.set("ogk_session", session_cookie)

    # 1. Lưu chính sách Whitelist
    dummy_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    res1 = client.post(
        "/dashboard/policy/save",
        data={
            "child_id": child.id,
            "daily_minutes": 90,
            "start_time": "08:00",
            "end_time": "20:00",
            "app_mode": "whitelist",
            "blocked_apps": f"notepad.exe:{dummy_hash}\ncalc.exe",
            "blocked_domains": "google.com",
        },
    )
    assert res1.status_code == 200

    pol1 = db_session.query(models.Policy).filter(models.Policy.child_id == child.id).order_by(models.Policy.version.desc()).first()
    app_rules1 = json.loads(pol1.app_rules_json)
    assert app_rules1["mode"] == "whitelist"
    assert f"notepad.exe:{dummy_hash}" in app_rules1["whitelist"]
    assert "calc.exe" in app_rules1["whitelist"]

    # 2. Cập nhật chính sách sang Blacklist
    res2 = client.post(
        "/dashboard/policy/save",
        data={
            "child_id": child.id,
            "daily_minutes": 60,
            "start_time": "08:00",
            "end_time": "20:00",
            "app_mode": "blacklist",
            "blocked_apps": f"game.exe:{dummy_hash}",
            "blocked_domains": "tiktok.com",
        },
    )
    assert res2.status_code == 200

    pol2 = db_session.query(models.Policy).filter(models.Policy.child_id == child.id).order_by(models.Policy.version.desc()).first()
    assert pol2.version == pol1.version + 1
    app_rules2 = json.loads(pol2.app_rules_json)
    assert app_rules2["mode"] == "blacklist"
    assert f"game.exe:{dummy_hash}" in app_rules2["blacklist"]


def test_sha256_rule_variations_parsing_and_blocking():
    """Kiểm tra toàn diện tất cả định dạng nhập SHA-256:
    - tên tiến trình:sha-256 (game.exe:hash, game.exe:sha256:hash, game.exe:sha-256:hash, game.exe hash)
    - chỉ nhập sha-256 (hash, sha256:hash, sha-256:hash, SHA256: hash)
    - đầu ra certutil cách nhau bằng khoảng trắng
    - chặn cả khi đổi tên tiến trình (anti-cheat)
    """
    dummy_hash = "3a52140a3224b7a19280e22709db17e45ad5b0c95a28c304d6e9f1a23456789a"
    certutil_hash_spaced = "3a 52 14 0a 32 24 b7 a1 92 80 e2 27 09 db 17 e4 5a d5 b0 c9 5a 28 c3 04 d6 e9 f1 a2 34 56 78 9a"

    # 1. Các định dạng "tên tiến trình:sha-256"
    for inp in [
        f"game.exe:{dummy_hash}",
        f"game.exe:sha256:{dummy_hash}",
        f"game.exe:sha-256:{dummy_hash}",
        f"game.exe {dummy_hash}",
        f"C:\\Games\\game.exe:{dummy_hash}",
    ]:
        p = parse_app_rule_entry(inp)
        assert p["name"] == "game.exe", f"Failed on input: {inp}"
        assert p["sha256"] == dummy_hash, f"Failed on input: {inp}"

        # Cả phía server cũng phân tích chính xác tương tự
        p_srv = security.parse_app_rule_entry(inp)
        assert p_srv["name"] == "game.exe"
        assert p_srv["sha256"] == dummy_hash

    # 2. Các định dạng "chỉ nhập sha-256"
    for inp in [
        dummy_hash,
        f"sha256:{dummy_hash}",
        f"sha-256:{dummy_hash}",
        f"SHA256: {dummy_hash}",
        f"sha-256 = {dummy_hash}",
        certutil_hash_spaced,
        f"sha256: {certutil_hash_spaced}",
    ]:
        p = parse_app_rule_entry(inp)
        assert p["name"] is None, f"Expected name=None for input: {inp}, got {p['name']}"
        assert p["sha256"] == dummy_hash, f"Expected sha256={dummy_hash} for input: {inp}, got {p['sha256']}"

        p_srv = security.parse_app_rule_entry(inp)
        assert p_srv["name"] is None
        assert p_srv["sha256"] == dummy_hash

    # 3. Thực thi chặn: Quy tắc CHỈ NHẬP SHA-256 (không tên app)
    # Tiến trình game.exe có mã hash trùng khớp -> PHẢI BỊ CHẶN!
    is_blocked, reason, identified = check_process_rule(
        proc_name="random_game.exe",
        proc_sha256=dummy_hash,
        app_rules={"mode": "blacklist", "blacklist": [f"sha256:{dummy_hash}"]},
    )
    assert is_blocked is True
    assert "Khớp mã SHA-256 bị cấm" in reason

    # 4. Thực thi chặn: Quy tắc TÊN:SHA-256
    # Trẻ đổi tên game.exe thành calc.exe hòng qua mặt -> Vẫn bị nhận diện qua SHA-256 và BỊ CHẶN!
    is_blocked, reason, identified = check_process_rule(
        proc_name="calc.exe",
        proc_sha256=dummy_hash,
        app_rules={"mode": "blacklist", "blacklist": [f"game.exe:sha256:{dummy_hash}"]},
    )
    assert is_blocked is True
    assert "Khớp mã SHA-256 bị cấm" in reason or "giả mạo" in reason

    # 5. Nếu tiến trình có hash KHÁC với hash bị cấm của quy tắc tên:hash
    diff_hash = "bbbb1111222233334444555566667777888899990000aaaabbbbccccddddeeee"
    is_blocked, reason, identified = check_process_rule(
        proc_name="game.exe",
        proc_sha256=diff_hash,
        app_rules={"mode": "blacklist", "blacklist": [f"game.exe:sha256:{dummy_hash}"]},
    )
    assert is_blocked is False

