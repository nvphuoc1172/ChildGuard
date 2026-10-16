"""Unit tests cho HostsBlocker & DNS Proxy trong ChildGuard Agent."""
import os
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Thêm app/agent vào sys.path để import các module của agent
agent_dir = Path(__file__).resolve().parent.parent / "agent"
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

from dns_proxy import (
    TAG_END,
    TAG_START,
    DNSProxyServer,
    HostsBlocker,
    build_blocked_response,
    normalize_domain,
    parse_dns_domain,
)


def test_normalize_domain():
    assert normalize_domain("http://example.com/some/path") == "example.com"
    assert normalize_domain("https://sub.domain.org:8443/test?q=1") == "sub.domain.org"
    assert normalize_domain("FACEBOOK.COM") == "facebook.com"
    assert normalize_domain("   tiktok.com/   ") == "tiktok.com"
    assert normalize_domain("") == ""


def test_hosts_blocker_apply_and_clear_blacklist(tmp_path: Path):
    hosts_file = tmp_path / "hosts"
    initial_content = (
        "# Copyright (c) 1993-2009 Microsoft Corp.\n"
        "127.0.0.1       localhost\n"
        "::1             localhost\n"
    )
    hosts_file.write_text(initial_content, encoding="utf-8")

    # 1. Thêm blacklist
    raw_domains = ["facebook.com", "tiktok.com"]
    success = HostsBlocker.apply_blacklist(raw_domains, hosts_path=hosts_file)
    assert success is True

    updated_content = hosts_file.read_text(encoding="utf-8")
    assert "127.0.0.1       localhost" in updated_content
    assert TAG_START in updated_content
    assert TAG_END in updated_content
    assert "0.0.0.0 facebook.com" in updated_content
    assert ":: facebook.com" in updated_content
    assert "0.0.0.0 www.facebook.com" in updated_content
    assert "0.0.0.0 tiktok.com" in updated_content

    # 2. Cập nhật blacklist mới (Idempotency, thay thế khối cũ)
    new_domains = ["youtube.com"]
    success2 = HostsBlocker.apply_blacklist(new_domains, hosts_path=hosts_file)
    assert success2 is True

    re_updated = hosts_file.read_text(encoding="utf-8")
    assert re_updated.count(TAG_START) == 1
    assert re_updated.count(TAG_END) == 1
    assert "youtube.com" in re_updated
    assert "facebook.com" not in re_updated

    # 3. Xóa blacklist (clear)
    success3 = HostsBlocker.clear(hosts_path=hosts_file)
    assert success3 is True

    cleared_content = hosts_file.read_text(encoding="utf-8")
    assert TAG_START not in cleared_content
    assert TAG_END not in cleared_content
    assert "127.0.0.1       localhost" in cleared_content


def test_hosts_blocker_handles_readonly_file(tmp_path: Path):
    hosts_file = tmp_path / "readonly_hosts"
    hosts_file.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    # Đặt cờ Read-Only (chỉ đọc)
    os.chmod(hosts_file, stat.S_IREAD)

    # HostsBlocker phải tự gỡ bỏ cờ read-only và ghi thành công
    domains = ["game.io"]
    success = HostsBlocker.apply_blacklist(domains, hosts_path=hosts_file)
    assert success is True

    content = hosts_file.read_text(encoding="utf-8")
    assert "0.0.0.0 game.io" in content


def test_hosts_blocker_elevated_fallback_called_on_permission_error(tmp_path: Path):
    hosts_file = tmp_path / "mock_hosts"
    hosts_file.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    # Giả lập sys.platform là win32 và ghi trực tiếp bị PermissionError
    with patch("sys.platform", "win32"):
        with patch.object(Path, "write_text", side_effect=PermissionError("Access is denied")):
            with patch.object(HostsBlocker, "_elevated_write_windows", return_value=True) as mock_elevated:
                success = HostsBlocker.apply_blacklist(["badsite.com"], hosts_path=hosts_file)
                assert success is True
                assert mock_elevated.called


def test_dns_proxy_is_domain_blocked():
    mock_storage = MagicMock()
    mock_storage.get_policy.return_value = {
        "version": 1,
        "domain_rules": {"blacklist": ["facebook.com", "tiktok.com"]},
    }
    mock_storage.check_connection_grace_period.return_value = "normal"

    proxy = DNSProxyServer(mock_storage)
    with patch.object(HostsBlocker, "apply_blacklist", return_value=True):
        proxy.sync_policy_rules()

    assert proxy.is_domain_blocked("facebook.com") is True
    assert proxy.is_domain_blocked("www.facebook.com") is True
    assert proxy.is_domain_blocked("sub.facebook.com") is True
    assert proxy.is_domain_blocked("google.com") is False
    assert proxy.is_domain_blocked("tiktok.com") is True


def test_parse_dns_domain_and_build_blocked_response():
    # DNS query packet mẫu cho domain "example.com" Type A
    # Header: 12 bytes
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    # Question: \x07example\x03com\x00 + Type A (1) + Class IN (1)
    qname = b"\x07example\x03com\x00"
    qtype_class = b"\x00\x01\x00\x01"
    packet = header + qname + qtype_class

    domain, qname_end = parse_dns_domain(packet)
    assert domain == "example.com"
    assert qname_end == 12 + len(qname)

    resp = build_blocked_response(packet, qname_end)
    assert resp[:2] == b"\x12\x34"  # Tx ID giữ nguyên
    assert resp[2:4] == b"\x81\x80"  # Response flags
    assert resp[-4:] == b"\x00\x00\x00\x00"  # Trả về IPv4 0.0.0.0
