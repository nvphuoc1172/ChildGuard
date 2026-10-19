"""Unit tests cho HostsBlocker & DNS Proxy trong ChildGuard Agent."""
import os
import socket
import stat
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Thêm app/agent vào sys.path để import các module của agent
agent_dir = Path(__file__).resolve().parent.parent / "agent"
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

from dns_proxy import (
    BING_SAFESEARCH_IPV4,
    BING_SAFESEARCH_IPV6,
    GOOGLE_SAFESEARCH_IPV4,
    GOOGLE_SAFESEARCH_IPV6,
    TAG_END,
    TAG_SAFESEARCH_END,
    TAG_SAFESEARCH_START,
    TAG_START,
    YOUTUBE_SAFESEARCH_IPV4,
    YOUTUBE_SAFESEARCH_IPV6,
    DNSProxyServer,
    HostsBlocker,
    WindowsDNSManager,
    build_blocked_response,
    build_safesearch_response,
    get_safesearch_target,
    is_bypass_domain,
    normalize_domain,
    parse_dns_domain,
)


def test_windows_dns_manager_routes_and_restores_active_adapters():
    manager = WindowsDNSManager()
    responses = [
        MagicMock(
            returncode=0,
            stdout='[{"InterfaceIndex":7,"ServerAddresses":["192.0.2.53"]}]',
            stderr="",
        ),
        MagicMock(returncode=0, stdout="", stderr=""),
        MagicMock(returncode=0, stdout="", stderr=""),
    ]
    with patch("dns_proxy.sys.platform", "win32"), patch.object(
        manager, "_run_powershell", side_effect=responses
    ) as run_ps:
        assert manager.enable_local_proxy() is True
        assert manager.configured is True
        assert "127.0.0.1" in run_ps.call_args_list[1].args[0]
        manager.restore()
        assert "192.0.2.53" in run_ps.call_args_list[2].args[0]
        assert manager.configured is False


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
    success = HostsBlocker.apply_blacklist(raw_domains, hosts_path=hosts_file, enforce_safesearch=False)
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
    success2 = HostsBlocker.apply_blacklist(new_domains, hosts_path=hosts_file, enforce_safesearch=False)
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
    success = HostsBlocker.apply_blacklist(domains, hosts_path=hosts_file, enforce_safesearch=False)
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


# =========================================================================
# BỔ SUNG CÁC TEST CASES MỚI CHO BƯỚC 1: SAFESEARCH & DANH SÁCH MIỄN CHẶN NT6
# =========================================================================

def test_permanent_bypass_list_cannot_be_blocked(tmp_path: Path):
    """Kiểm tra Nguyên tắc NT6: Danh sách miễn chặn vĩnh viễn không bao giờ bị chặn."""
    # 1. Các tên miền cứu trợ khẩn cấp, tổng đài 111, giáo dục
    assert is_bypass_domain("tongdai111.vn") is True
    assert is_bypass_domain("www.tongdai111.vn") is True
    assert is_bypass_domain("111.vn") is True
    assert is_bypass_domain("treem.gov.vn") is True
    assert is_bypass_domain("chinhphu.vn") is True
    assert is_bypass_domain("dichvucong.gov.vn") is True
    assert is_bypass_domain("moet.gov.vn") is True
    assert is_bypass_domain("hcmus.edu.vn") is True
    assert is_bypass_domain("portal.hcmus.edu.vn") is True
    assert is_bypass_domain("thpt-nguyenhue.edu.vn") is True
    assert is_bypass_domain("capcuu115.vn") is True

    # Tên miền thông thường không thuộc danh sách miễn chặn
    assert is_bypass_domain("facebook.com") is False
    assert is_bypass_domain("gameonline.vn") is False

    # 2. Ngay cả khi phụ huynh nhập nhầm tongdai111.vn vào blacklist:
    mock_storage = MagicMock()
    mock_storage.get_policy.return_value = {
        "version": 2,
        "domain_rules": {
            "blacklist": ["tongdai111.vn", "hcmus.edu.vn", "badsite.com"],
            "safesearch": True,
        },
    }
    mock_storage.check_connection_grace_period.return_value = "normal"

    proxy = DNSProxyServer(mock_storage)
    with patch.object(HostsBlocker, "apply_blacklist", return_value=True):
        proxy.sync_policy_rules()

    # tongdai111.vn và hcmus.edu.vn tuyệt đối KHÔNG bị chặn
    assert proxy.is_domain_blocked("tongdai111.vn") is False
    assert proxy.is_domain_blocked("hcmus.edu.vn") is False
    assert proxy.is_domain_blocked("portal.hcmus.edu.vn") is False
    # Nhưng badsite.com vẫn bị chặn bình thường
    assert proxy.is_domain_blocked("badsite.com") is True

    # 3. HostsBlocker cũng phải lọc bỏ các tên miền bypass không ghi vào file hosts
    hosts_file = tmp_path / "bypass_hosts"
    hosts_file.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    HostsBlocker.apply_blacklist(
        ["tongdai111.vn", "hcmus.edu.vn", "badsite.com"],
        hosts_path=hosts_file,
        enforce_safesearch=False,
    )
    content = hosts_file.read_text(encoding="utf-8")
    assert "0.0.0.0 badsite.com" in content
    assert "tongdai111.vn" not in content
    assert "hcmus.edu.vn" not in content


def test_safesearch_target_detection():
    """Kiểm tra nhận diện các dịch vụ tìm kiếm Google, Bing, YouTube cần cưỡng chế SafeSearch."""
    # Google Search
    g1 = get_safesearch_target("www.google.com")
    assert g1 is not None
    assert g1["ipv4"] == GOOGLE_SAFESEARCH_IPV4
    assert g1["cname"] == "forcesafesearch.google.com"

    g2 = get_safesearch_target("google.com.vn")
    assert g2 is not None
    assert g2["ipv4"] == GOOGLE_SAFESEARCH_IPV4

    g3 = get_safesearch_target("google.co.uk")
    assert g3 is not None
    assert g3["ipv4"] == GOOGLE_SAFESEARCH_IPV4

    # Bing
    b1 = get_safesearch_target("bing.com")
    assert b1 is not None
    assert b1["ipv4"] == BING_SAFESEARCH_IPV4
    assert b1["cname"] == "strict.bing.com"

    b2 = get_safesearch_target("www.bing.com")
    assert b2 is not None
    assert b2["ipv4"] == BING_SAFESEARCH_IPV4

    # YouTube
    y1 = get_safesearch_target("youtube.com")
    assert y1 is not None
    assert y1["ipv4"] == YOUTUBE_SAFESEARCH_IPV4
    assert y1["cname"] == "restrict.youtube.com"

    y2 = get_safesearch_target("www.youtube.com")
    assert y2 is not None
    assert y2["ipv4"] == YOUTUBE_SAFESEARCH_IPV4

    y3 = get_safesearch_target("m.youtube.com")
    assert y3 is not None

    # Không áp dụng cho chính các domain VIP endpoint (tránh lặp vô hạn)
    assert get_safesearch_target("forcesafesearch.google.com") is None
    assert get_safesearch_target("strict.bing.com") is None
    assert get_safesearch_target("restrict.youtube.com") is None

    # Không áp dụng cho các dịch vụ khác của Google (Mail, Drive...)
    assert get_safesearch_target("mail.google.com") is None
    assert get_safesearch_target("drive.google.com") is None
    assert get_safesearch_target("accounts.google.com") is None

    # Domain bình thường
    assert get_safesearch_target("github.com") is None


def test_build_safesearch_dns_response():
    """Kiểm tra tạo gói tin DNS Response RFC-1035 chứa VIP SafeSearch cho Type A và Type AAAA."""
    # Query Type A cho www.google.com
    header = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"\x03www\x06google\x03com\x00"
    qtype_a = b"\x00\x01\x00\x01"
    packet_a = header + qname + qtype_a

    domain, qname_end = parse_dns_domain(packet_a)
    assert domain == "www.google.com"

    target = get_safesearch_target(domain)
    assert target is not None

    # Type A response
    resp_a = build_safesearch_response(packet_a, qname_end, target)
    assert resp_a[:2] == b"\xaa\xbb"
    assert resp_a[2:4] == b"\x81\x80"
    # Kiểm tra IPv4 cuối gói tin
    assert resp_a[-4:] == socket.inet_aton(GOOGLE_SAFESEARCH_IPV4)

    # Query Type AAAA (28) cho www.google.com
    qtype_aaaa = struct.pack(">H", 28) + b"\x00\x01"
    packet_aaaa = header + qname + qtype_aaaa
    domain_aaaa, qname_end_aaaa = parse_dns_domain(packet_aaaa)

    resp_aaaa = build_safesearch_response(packet_aaaa, qname_end_aaaa, target)
    assert resp_aaaa[:2] == b"\xaa\xbb"
    assert resp_aaaa[2:4] == b"\x81\x80"
    # Kiểm tra IPv6 cuối gói tin
    assert resp_aaaa[-16:] == socket.inet_pton(socket.AF_INET6, GOOGLE_SAFESEARCH_IPV6)


def test_hosts_blocker_dual_layer_safesearch(tmp_path: Path):
    """Kiểm tra HostsBlocker hỗ trợ cưỡng chế SafeSearch cấp file hosts."""
    hosts_file = tmp_path / "safesearch_hosts"
    hosts_file.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    # 1. Bật SafeSearch
    success = HostsBlocker.apply_blacklist(["badgame.io"], hosts_path=hosts_file, enforce_safesearch=True)
    assert success is True

    content = hosts_file.read_text(encoding="utf-8")
    assert "127.0.0.1 localhost" in content
    assert TAG_START in content
    assert "0.0.0.0 badgame.io" in content
    assert TAG_SAFESEARCH_START in content
    assert TAG_SAFESEARCH_END in content
    assert f"{GOOGLE_SAFESEARCH_IPV4} www.google.com" in content
    assert f"{BING_SAFESEARCH_IPV4} www.bing.com" in content
    assert f"{YOUTUBE_SAFESEARCH_IPV4} www.youtube.com" in content

    # 2. Xóa sạch file hosts
    HostsBlocker.clear(hosts_path=hosts_file)
    cleared = hosts_file.read_text(encoding="utf-8")
    assert TAG_START not in cleared
    assert TAG_SAFESEARCH_START not in cleared
    assert "127.0.0.1 localhost" in cleared


def test_dns_proxy_handles_safesearch_and_bypass_query():
    """Kiểm tra quy trình xử lý query trong DNSProxyServer."""
    mock_storage = MagicMock()
    mock_storage.get_policy.return_value = {
        "version": 1,
        "domain_rules": {
            "blacklist": ["badgame.com"],
            "safesearch": True,
        },
    }
    proxy = DNSProxyServer(mock_storage)
    proxy.sock = MagicMock()

    with patch.object(HostsBlocker, "apply_blacklist", return_value=True):
        proxy.sync_policy_rules()

    # Query 1: Google Search -> Áp dụng SafeSearch
    packet_g = b"\x11\x22\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01"
    client_addr = ("127.0.0.1", 54321)
    proxy.handle_query(packet_g, client_addr)

    # Đảm bảo proxy.sock.sendto được gọi trả về VIP IP
    assert proxy.sock.sendto.called
    sent_data, addr = proxy.sock.sendto.call_args[0]
    assert addr == client_addr
    assert sent_data[-4:] == socket.inet_aton(GOOGLE_SAFESEARCH_IPV4)

    # Query 2: Tên miền bị cấm -> Trả về 0.0.0.0
    proxy.sock.reset_mock()
    packet_bad = b"\x33\x44\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07badgame\x03com\x00\x00\x01\x00\x01"
    with patch.object(proxy, "notify_dns_blocked") as mock_notify:
        proxy.handle_query(packet_bad, client_addr)
        assert proxy.sock.sendto.called
        sent_data, _ = proxy.sock.sendto.call_args[0]
        assert sent_data[-4:] == b"\x00\x00\x00\x00"

    # Query 3: Tên miền miễn chặn (tongdai111.vn) -> Forward sang upstream, không bao giờ chặn
    proxy.sock.reset_mock()
    packet_111 = b"\x55\x66\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0atongdai111\x02vn\x00\x00\x01\x00\x01"
    with patch.object(proxy, "_forward_query") as mock_fwd:
        proxy.handle_query(packet_111, client_addr)
        assert mock_fwd.called
