"""DNS Proxy 127.0.0.1:53 & Windows Hosts Filter — xem mục 3 và 10.3 trong Design.md.

Chịu trách nhiệm:
1. Đồng bộ danh sách tên miền bị cấm vào Windows Hosts (chặn triệt để cả IPv4/IPv6, mọi trình duyệt Edge/Chrome/Firefox).
2. Danh sách Miễn chặn Vĩnh viễn (Nguyên tắc NT6): Cổng trường học (*.edu.vn, *.gov.vn), Tổng đài Quốc gia 111, Khẩn cấp.
3. Cưỡng chế SafeSearch của công cụ tìm kiếm (F2): Tự động chuyển hướng Google, Bing, YouTube sang chế độ lọc an toàn bắt buộc (SafeSearch/Strict/Restricted).
4. Lắng nghe UDP query trên 127.0.0.1:53 theo chuẩn RFC 1035:
   - Type A (1) -> Trả về 0.0.0.0 (nếu bị cấm) hoặc SafeSearch VIP IP (nếu là search engine)
   - Type AAAA (28) -> Trả về :: (nếu bị cấm) hoặc SafeSearch IPv6 VIP
   - Type khác (HTTPS/SVCB) -> Trả về NXDOMAIN (nếu bị cấm) hoặc NOERROR để fallback IPv4
5. Ghi nhận domain_query/blocked_domain với subject là registrable domain.
6. Chuyển tiếp (forward) các truy vấn được phép tới Upstream DNS (8.8.8.8:53).
"""
from __future__ import annotations

import base64
import ctypes
import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

try:
    from event_contract import normalize_domain_subject
except ImportError:  # package import (for example: agent.dns_proxy)
    from .event_contract import normalize_domain_subject
from typing import List, Set, Tuple

from storage import AgentStorage

TAG_START = "# --- CHILDGUARD_MANAGED_BLOCK_START ---"
TAG_END = "# --- CHILDGUARD_MANAGED_BLOCK_END ---"
TAG_SAFESEARCH_START = "# --- CHILDGUARD_SAFESEARCH_START ---"
TAG_SAFESEARCH_END = "# --- CHILDGUARD_SAFESEARCH_END ---"

# -------------------------------------------------------------
# CẤU HÌNH DANH SÁCH MIỄN CHẶN VĨNH VIỄN (NT6)
# -------------------------------------------------------------
PERMANENT_BYPASS_DOMAINS: Set[str] = {
    # 1. Tổng đài Quốc gia Bảo vệ Trẻ em 111 & Cục Trẻ em (Luật Trẻ em 2016, Nghị định 13/2023)
    "tongdai111.vn",
    "www.tongdai111.vn",
    "111.vn",
    "www.111.vn",
    "treem.gov.vn",
    "www.treem.gov.vn",
    # 2. Cổng Thông tin Chính phủ, Dịch vụ công & Khẩn cấp Quốc gia
    "chinhphu.vn",
    "www.chinhphu.vn",
    "baochinhphu.vn",
    "www.baochinhphu.vn",
    "dichvucong.gov.vn",
    "www.dichvucong.gov.vn",
    "capcuu115.vn",
    "moh.gov.vn",
    "www.moh.gov.vn",
    # 3. Cổng Thông tin Giáo dục & Đại học
    "moet.gov.vn",
    "www.moet.gov.vn",
    "hcmus.edu.vn",
    "www.hcmus.edu.vn",
    "vnuhcm.edu.vn",
    "www.vnuhcm.edu.vn",
    # 4. SafeSearch VIP Endpoints (để không tự chặn chính SafeSearch)
    "forcesafesearch.google.com",
    "strict.bing.com",
    "restrict.youtube.com",
    "safe.duckduckgo.com",
    # 5. Localhost & Loopback
    "localhost",
}

# -------------------------------------------------------------
# CẤU HÌNH CƯỠNG CHẾ SAFESEARCH (F2 - BẮT BUỘC)
# -------------------------------------------------------------
GOOGLE_SAFESEARCH_IPV4 = "216.239.38.120"
GOOGLE_SAFESEARCH_IPV6 = "2001:4860:4802:32::78"
GOOGLE_SAFESEARCH_CNAME = "forcesafesearch.google.com"

BING_SAFESEARCH_IPV4 = "204.79.197.220"
BING_SAFESEARCH_IPV6 = "2620:1ec:c11::200"
BING_SAFESEARCH_CNAME = "strict.bing.com"

YOUTUBE_SAFESEARCH_IPV4 = "216.239.38.120"
YOUTUBE_SAFESEARCH_IPV6 = "2001:4860:4802:32::78"
YOUTUBE_SAFESEARCH_CNAME = "restrict.youtube.com"


def normalize_domain(d: str) -> str:
    """Chuẩn hóa tên miền: loại bỏ http://, https://, cổng, đường dẫn và query."""
    if not d:
        return ""
    d = d.lower().strip()
    if d.startswith("http://"):
        d = d[7:]
    elif d.startswith("https://"):
        d = d[8:]
    d = d.split("/")[0].split(":")[0].strip()
    return d


def is_bypass_domain(domain: str) -> bool:
    """Kiểm tra tên miền có thuộc Danh sách Miễn chặn Vĩnh viễn (NT6) hay không.

    Theo Nguyên tắc NT6:
    1. Tổng đài Quốc gia Bảo vệ Trẻ em 111 (tongdai111.vn, 111.vn) và Cục Trẻ em (treem.gov.vn).
    2. Cổng dịch vụ công, Cổng thông tin Chính phủ, Bộ GD&ĐT, Bộ Y tế và dịch vụ khẩn cấp.
    3. Tất cả các cổng thông tin trường học và giáo dục có đuôi *.edu.vn hoặc cơ quan *.gov.vn.
    4. Các địa chỉ phân giải SafeSearch chuẩn.

    Những tên miền này TUYỆT ĐỐI KHÔNG BỊ CHẶN trong bất kỳ tình huống nào
    (kể cả khi phụ huynh vô tình đưa vào danh sách đen hoặc khi hệ thống ở chế độ degraded).
    """
    if not domain:
        return False
    d = normalize_domain(domain)
    if not d:
        return False
    if d in PERMANENT_BYPASS_DOMAINS:
        return True
    for bp in PERMANENT_BYPASS_DOMAINS:
        if d == bp or d.endswith("." + bp):
            return True
    # Miễn chặn toàn bộ tên miền cơ quan giáo dục và cơ quan chính phủ Việt Nam
    if d.endswith(".edu.vn") or d.endswith(".gov.vn"):
        return True
    return False


def is_google_search_domain(domain: str) -> bool:
    """Kiểm tra xem tên miền có phải là dịch vụ tìm kiếm Google cần cưỡng chế SafeSearch hay không."""
    d = normalize_domain(domain)
    if d == GOOGLE_SAFESEARCH_CNAME:
        return False
    base = d[4:] if d.startswith("www.") else d
    # Chỉ khớp các domain tìm kiếm Google: google.com, google.com.vn, google.com.sg, google.co.uk...
    if base == "google.com" or base.startswith("google."):
        return True
    return False


def is_bing_search_domain(domain: str) -> bool:
    """Kiểm tra xem tên miền có phải là dịch vụ tìm kiếm Bing cần cưỡng chế SafeSearch hay không."""
    d = normalize_domain(domain)
    if d == BING_SAFESEARCH_CNAME:
        return False
    base = d[4:] if d.startswith("www.") else d
    if base == "bing.com" or base.startswith("bing.") or d in ("cn.bing.com", "global.bing.com"):
        return True
    return False


def is_youtube_domain(domain: str) -> bool:
    """Kiểm tra xem tên miền có phải là YouTube cần cưỡng chế Restricted Mode hay không."""
    d = normalize_domain(domain)
    if d == YOUTUBE_SAFESEARCH_CNAME:
        return False
    base = d[4:] if d.startswith("www.") else d
    if base == "youtube.com" or base.startswith("youtube."):
        return True
    if d in ("m.youtube.com", "youtubei.googleapis.com", "youtube-nocookie.com"):
        return True
    return False


def get_safesearch_target(domain: str) -> dict | None:
    """Xác định xem tên miền có cần cưỡng chế SafeSearch hay không.

    Trả về dict chứa thông tin IPv4, IPv6, CNAME hoặc None.
    """
    if not domain:
        return None
    d = normalize_domain(domain)
    if not d:
        return None

    if is_google_search_domain(d):
        return {
            "service": "Google SafeSearch",
            "cname": GOOGLE_SAFESEARCH_CNAME,
            "ipv4": GOOGLE_SAFESEARCH_IPV4,
            "ipv6": GOOGLE_SAFESEARCH_IPV6,
        }
    if is_bing_search_domain(d):
        return {
            "service": "Bing Strict Search",
            "cname": BING_SAFESEARCH_CNAME,
            "ipv4": BING_SAFESEARCH_IPV4,
            "ipv6": BING_SAFESEARCH_IPV6,
        }
    if is_youtube_domain(d):
        return {
            "service": "YouTube Restricted Mode",
            "cname": YOUTUBE_SAFESEARCH_CNAME,
            "ipv4": YOUTUBE_SAFESEARCH_IPV4,
            "ipv6": YOUTUBE_SAFESEARCH_IPV6,
        }
    return None


class HostsBlocker:
    """Quản lý file hosts của Windows để chặn tên miền cấp hệ điều hành (không thể bypass qua DNS dự phòng hay DoH)."""

    @staticmethod
    def is_admin() -> bool:
        """Kiểm tra quyền Administrator của tiến trình hiện tại trên Windows."""
        if sys.platform != "win32":
            return os.geteuid() == 0 if hasattr(os, "geteuid") else True
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @staticmethod
    def get_hosts_path() -> Path:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        return Path(system_root) / "System32" / "drivers" / "etc" / "hosts"

    @classmethod
    def setup_permissions(cls, hosts_path: Path | None = None) -> bool:
        """Cấp quyền sửa đổi (Modify) file hosts cho nhóm Users (*S-1-5-32-545) khi có quyền Admin.

        Việc này giúp các lần ghi sau (kể cả khi tiến trình chạy dưới quyền User thông thường)
        có thể ghi đè file hosts mà không cần quyền Administrator hay hiển thị UAC prompt.
        """
        if sys.platform != "win32":
            return True
        if hosts_path is None:
            hosts_path = cls.get_hosts_path()
        if not hosts_path.exists():
            return False
        if not cls.is_admin():
            return False

        try:
            # Gỡ thuộc tính chỉ đọc (Read-only)
            os.chmod(hosts_path, stat.S_IWRITE | stat.S_IREAD)
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(hosts_path), 0x80)  # FILE_ATTRIBUTE_NORMAL
            except Exception:
                pass

            # Cấp quyền Modify (M) cho nhóm Users (*S-1-5-32-545 là SID cố định cho BUILTIN\Users)
            cmd = f'icacls "{hosts_path}" /grant "*S-1-5-32-545:(M)" /c'
            res = subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            return res.returncode == 0
        except Exception:
            return False

    @classmethod
    def _flush_dns(cls):
        """Xóa cache DNS của Windows để áp dụng ngay lập tức."""
        if sys.platform == "win32":
            try:
                subprocess.run("ipconfig /flushdns", shell=True, capture_output=True, timeout=5)
            except Exception:
                pass

    @classmethod
    def _elevated_write_windows(cls, hosts_path: Path, content: str) -> bool:
        """Ghi file hosts bằng cách kích hoạt UAC thông qua PowerShell Start-Process -Verb RunAs.

        Đồng thời cấp quyền Modify cho nhóm Users (*S-1-5-32-545) để lần sau không cần UAC lại.
        """
        temp_file = None
        try:
            temp_fd, temp_path = tempfile.mkstemp(prefix="ogk_hosts_", suffix=".tmp", text=True)
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                f.write(content)
            temp_file = Path(temp_path)

            ps_bin = shutil.which("powershell") or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

            # Script PowerShell chạy dưới quyền Administrator
            ps_script = (
                "$ErrorActionPreference = 'Stop'\n"
                f"$src = @'\n{temp_file}\n'@\n"
                f"$dst = @'\n{hosts_path}\n'@\n"
                "if (Test-Path $dst) {\n"
                "    Set-ItemProperty -Path $dst -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue\n"
                "    attrib -r $dst\n"
                "}\n"
                "Copy-Item -Path $src -Destination $dst -Force\n"
                '& icacls.exe $dst /grant "*S-1-5-32-545:(M)" /c | Out-Null\n'
                "ipconfig /flushdns | Out-Null\n"
            )
            encoded_script = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")

            elevate_cmd = (
                f'Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden '
                f'-ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_script}"'
            )

            res = subprocess.run(
                [ps_bin, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", elevate_cmd],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if res.returncode == 0:
                print("[Hosts Blocker] ✓ Đã ghi file hosts và cấp quyền Modify cho Users qua UAC thành công.")
                return True
            else:
                err_msg = res.stderr.strip() if res.stderr else f"Exit code {res.returncode}"
                print(f"[Hosts Blocker] Cảnh báo lỗi cập nhật file hosts (cần quyền Admin): UAC thất bại ({err_msg})")
                return False
        except subprocess.TimeoutExpired:
            print("[Hosts Blocker] Cảnh báo: Quá thời gian chờ xác nhận quyền Administrator (UAC timeout).")
            return False
        except Exception as e:
            print(f"[Hosts Blocker] Cảnh báo lỗi cập nhật file hosts (cần quyền Admin): {e}")
            return False
        finally:
            if temp_file and temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass

    @classmethod
    def _write_hosts(cls, hosts_path: Path, content: str) -> bool:
        """Ghi nội dung vào file hosts với cơ chế đa tầng xử lý quyền."""
        # 1. Gỡ thuộc tính Read-only nếu có
        try:
            if hosts_path.exists():
                os.chmod(hosts_path, stat.S_IWRITE | stat.S_IREAD)
                if sys.platform == "win32":
                    try:
                        ctypes.windll.kernel32.SetFileAttributesW(str(hosts_path), 0x80)  # FILE_ATTRIBUTE_NORMAL
                    except Exception:
                        pass
        except Exception:
            pass

        # 2. Thử ghi trực tiếp (thành công nếu có quyền Admin hoặc file đã được cấp Modify cho Users)
        try:
            hosts_path.write_text(content, encoding="utf-8")
            cls.setup_permissions(hosts_path)
            cls._flush_dns()
            return True
        except (PermissionError, OSError):
            pass

        # 3. Fallback trên Windows: Nâng quyền ghi qua UAC
        if sys.platform == "win32":
            print("[Hosts Blocker] Tiến trình chưa có quyền ghi file hosts. Đang yêu cầu nâng quyền Administrator...")
            return cls._elevated_write_windows(hosts_path, content)

        return False

    @classmethod
    def apply_blacklist(
        cls,
        raw_domains: List[str],
        hosts_path: Path | None = None,
        enforce_safesearch: bool = True,
    ) -> bool:
        """Áp dụng danh sách tên miền bị chặn và bản ghi SafeSearch VIP vào file hosts."""
        if hosts_path is None:
            if sys.platform != "win32":
                return True
            hosts_path = cls.get_hosts_path()

        try:
            content = ""
            if hosts_path.exists():
                content = hosts_path.read_text(encoding="utf-8", errors="ignore")

            # Xóa các khối quản lý cũ nếu đã tồn tại
            if TAG_START in content and TAG_END in content:
                before = content.split(TAG_START)[0]
                after = content.split(TAG_END)[1]
                content = before.rstrip() + "\n" + after.lstrip()

            if TAG_SAFESEARCH_START in content and TAG_SAFESEARCH_END in content:
                before_ss = content.split(TAG_SAFESEARCH_START)[0]
                after_ss = content.split(TAG_SAFESEARCH_END)[1]
                content = before_ss.rstrip() + "\n" + after_ss.lstrip()

            content = content.strip()

            # 1. Tạo khối Blacklist (tự động bỏ qua các tên miền thuộc bypass list NT6)
            new_block_lines = []
            seen_blocked_domains: Set[str] = set()

            if raw_domains:
                new_block_lines.append(TAG_START)
                for raw in raw_domains:
                    d = normalize_domain(raw)
                    if not d or "." not in d:
                        continue
                    if is_bypass_domain(d):
                        print(f"[Hosts Blocker] ⚠️ Bỏ qua tên miền miễn chặn vĩnh viễn (NT6): {d}")
                        continue

                    # Mở rộng domain để chặn cả www và subdomain thường gặp
                    targets = [d]
                    if d.startswith("www."):
                        targets.append(d[4:])
                    else:
                        targets.append(f"www.{d}")
                    if not d.startswith("m.") and len(d.split(".")) == 2:
                        targets.append(f"m.{d}")

                    for target in targets:
                        if is_bypass_domain(target):
                            continue
                        if target not in seen_blocked_domains:
                            seen_blocked_domains.add(target)
                            new_block_lines.append(f"0.0.0.0 {target}")
                            new_block_lines.append(f":: {target}")

                new_block_lines.append(TAG_END)

            # 2. Tạo khối SafeSearch (nếu được kích hoạt và tên miền chưa bị chặn hoàn toàn)
            safesearch_lines = []
            if enforce_safesearch:
                safesearch_lines.append(TAG_SAFESEARCH_START)

                # Google SafeSearch VIP
                google_targets = [
                    "forcesafesearch.google.com",
                    "www.google.com",
                    "google.com",
                    "www.google.com.vn",
                    "google.com.vn",
                ]
                for g in google_targets:
                    if g not in seen_blocked_domains:
                        safesearch_lines.append(f"{GOOGLE_SAFESEARCH_IPV4} {g}")
                        safesearch_lines.append(f"{GOOGLE_SAFESEARCH_IPV6} {g}")

                # Bing Strict VIP
                bing_targets = [
                    "strict.bing.com",
                    "www.bing.com",
                    "bing.com",
                    "cn.bing.com",
                ]
                for b in bing_targets:
                    if b not in seen_blocked_domains:
                        safesearch_lines.append(f"{BING_SAFESEARCH_IPV4} {b}")
                        safesearch_lines.append(f"{BING_SAFESEARCH_IPV6} {b}")

                # YouTube Restricted Mode VIP
                yt_targets = [
                    "restrict.youtube.com",
                    "www.youtube.com",
                    "youtube.com",
                    "m.youtube.com",
                    "youtubei.googleapis.com",
                    "youtube-nocookie.com",
                ]
                for y in yt_targets:
                    if y not in seen_blocked_domains:
                        safesearch_lines.append(f"{YOUTUBE_SAFESEARCH_IPV4} {y}")
                        safesearch_lines.append(f"{YOUTUBE_SAFESEARCH_IPV6} {y}")

                safesearch_lines.append(TAG_SAFESEARCH_END)

            # 3. Tổng hợp nội dung hoàn chỉnh
            parts = []
            if content:
                parts.append(content)
            if new_block_lines:
                parts.append("\n".join(new_block_lines))
            if safesearch_lines:
                parts.append("\n".join(safesearch_lines))

            final_content = ("\n\n".join(parts) + "\n") if parts else ""

            success = cls._write_hosts(hosts_path, final_content)
            if success:
                print(f"[Hosts Blocker] ✓ Đã đồng bộ {len(seen_blocked_domains)} tên miền cấm (SafeSearch: {'BẬT' if enforce_safesearch else 'TẮT'}) vào file hosts.")
                return True
            else:
                print(f"[Hosts Blocker] Cảnh báo lỗi cập nhật file hosts (cần quyền Admin): Không có quyền ghi vào {hosts_path}")
                return False
        except Exception as e:
            print(f"[Hosts Blocker] Cảnh báo lỗi cập nhật file hosts (cần quyền Admin): {e}")
            return False

    @classmethod
    def clear(cls, hosts_path: Path | None = None) -> bool:
        """Xóa sạch cả khối Blacklist và khối SafeSearch khỏi file hosts."""
        if hosts_path is None:
            if sys.platform != "win32":
                return True
            hosts_path = cls.get_hosts_path()

        try:
            if not hosts_path.exists():
                return True
            content = hosts_path.read_text(encoding="utf-8", errors="ignore")
            if TAG_START in content and TAG_END in content:
                before = content.split(TAG_START)[0]
                after = content.split(TAG_END)[1]
                content = before.rstrip() + "\n" + after.lstrip()

            if TAG_SAFESEARCH_START in content and TAG_SAFESEARCH_END in content:
                before_ss = content.split(TAG_SAFESEARCH_START)[0]
                after_ss = content.split(TAG_SAFESEARCH_END)[1]
                content = before_ss.rstrip() + "\n" + after_ss.lstrip()

            content = (content.strip() + "\n") if content.strip() else ""
            return cls._write_hosts(hosts_path, content)
        except Exception as e:
            print(f"[Hosts Blocker] Lỗi khi khôi phục file hosts: {e}")
            return False


def parse_dns_domain(data: bytes) -> Tuple[str, int]:
    """Trích xuất domain từ gói tin DNS truy vấn (RFC 1035).

    Bắt đầu từ byte 12 (sau header 12 bytes).
    """
    labels = []
    idx = 12
    while idx < len(data):
        length = data[idx]
        if length == 0:
            idx += 1
            break
        idx += 1
        labels.append(data[idx : idx + length].decode("ascii", errors="ignore"))
        idx += length
    domain = ".".join(labels).lower()
    return domain, idx


def build_blocked_response(query_data: bytes, qname_end: int) -> bytes:
    """Tạo gói DNS Response RFC-1035 hợp lệ tương ứng với loại bản ghi được yêu cầu:
    - Type A (1): Trả về 0.0.0.0
    - Type AAAA (28): Trả về ::
    - Type khác (HTTPS Type 65, ANY...): Trả về NXDOMAIN (RCODE=3)
    """
    if len(query_data) < qname_end + 4:
        # Fallback gói lỗi nếu packet quá ngắn
        return query_data[:2] + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00"

    tx_id = query_data[:2]
    qtype = struct.unpack(">H", query_data[qname_end : qname_end + 2])[0]
    question = query_data[12 : qname_end + 4]

    if qtype == 1:  # Type A (IPv4)
        flags = b"\x81\x80"  # QR=1, RA=1, No error
        header = tx_id + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        ans_name = b"\xc0\x0c"  # pointer to question
        ans_type = b"\x00\x01"  # A
        ans_class = b"\x00\x01"  # IN
        ans_ttl = struct.pack(">I", 300)
        ans_rdlen = b"\x00\x04"
        ans_rdata = b"\x00\x00\x00\x00"  # 0.0.0.0
        return header + question + ans_name + ans_type + ans_class + ans_ttl + ans_rdlen + ans_rdata

    elif qtype == 28:  # Type AAAA (IPv6)
        flags = b"\x81\x80"
        header = tx_id + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        ans_name = b"\xc0\x0c"
        ans_type = struct.pack(">H", 28)  # AAAA
        ans_class = b"\x00\x01"  # IN
        ans_ttl = struct.pack(">I", 300)
        ans_rdlen = b"\x00\x10"
        ans_rdata = b"\x00" * 16  # ::
        return header + question + ans_name + ans_type + ans_class + ans_ttl + ans_rdlen + ans_rdata

    else:
        # NXDOMAIN (RCODE=3) cho HTTPS (Type 65) và các truy vấn khác
        flags = b"\x81\x83"
        header = tx_id + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00"
        return header + question


def build_safesearch_response(query_data: bytes, qname_end: int, target: dict) -> bytes:
    """Tạo gói DNS Response RFC-1035 trả về bản ghi SafeSearch VIP (A, AAAA hoặc CNAME):
    - Type A (1): Trả về IPv4 SafeSearch VIP (216.239.38.120 cho Google/YouTube, 204.79.197.220 cho Bing)
    - Type AAAA (28): Trả về IPv6 SafeSearch VIP
    - Type CNAME (5): Trả về CNAME SafeSearch (forcesafesearch.google.com, strict.bing.com, restrict.youtube.com)
    - Type khác (HTTPS Type 65, ANY...): Trả về NOERROR (ANCOUNT=0) để client fallback sang Type A
    """
    if len(query_data) < qname_end + 4:
        return query_data[:2] + b"\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"

    tx_id = query_data[:2]
    qtype = struct.unpack(">H", query_data[qname_end : qname_end + 2])[0]
    question = query_data[12 : qname_end + 4]

    if qtype == 1:  # Type A (IPv4)
        flags = b"\x81\x80"
        header = tx_id + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        ans_name = b"\xc0\x0c"
        ans_type = b"\x00\x01"  # A
        ans_class = b"\x00\x01"  # IN
        ans_ttl = struct.pack(">I", 300)
        ans_rdlen = b"\x00\x04"
        ans_rdata = socket.inet_aton(target["ipv4"])
        return header + question + ans_name + ans_type + ans_class + ans_ttl + ans_rdlen + ans_rdata

    elif qtype == 28:  # Type AAAA (IPv6)
        ipv6_str = target.get("ipv6")
        if ipv6_str:
            flags = b"\x81\x80"
            header = tx_id + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00"
            ans_name = b"\xc0\x0c"
            ans_type = struct.pack(">H", 28)  # AAAA
            ans_class = b"\x00\x01"  # IN
            ans_ttl = struct.pack(">I", 300)
            ans_rdlen = b"\x00\x10"
            ans_rdata = socket.inet_pton(socket.AF_INET6, ipv6_str)
            return header + question + ans_name + ans_type + ans_class + ans_ttl + ans_rdlen + ans_rdata
        else:
            flags = b"\x81\x80"
            header = tx_id + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00"
            return header + question

    elif qtype == 5:  # Type CNAME
        cname = target.get("cname", "")
        labels = []
        for part in cname.split("."):
            part_b = part.encode("ascii")
            labels.append(bytes([len(part_b)]) + part_b)
        labels.append(b"\x00")
        cname_rdata = b"".join(labels)

        flags = b"\x81\x80"
        header = tx_id + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        ans_name = b"\xc0\x0c"
        ans_type = struct.pack(">H", 5)  # CNAME
        ans_class = b"\x00\x01"  # IN
        ans_ttl = struct.pack(">I", 300)
        ans_rdlen = struct.pack(">H", len(cname_rdata))
        return header + question + ans_name + ans_type + ans_class + ans_ttl + ans_rdlen + cname_rdata

    else:
        # NOERROR với 0 answer để browser fallback sang IPv4 Type A
        flags = b"\x81\x80"
        header = tx_id + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00"
        return header + question


class DNSProxyServer:
    def __init__(
        self,
        storage: AgentStorage,
        host: str = "127.0.0.1",
        port: int = 53,
        upstream_dns: str = "8.8.8.8",
        enforcer=None,
        notifier=None,
        enforce_safesearch: bool = True,
    ):
        self.storage = storage
        self.host = host
        self.port = port
        self.upstream_dns = upstream_dns
        self.enforcer = enforcer
        self.notifier = notifier
        self.enforce_safesearch = enforce_safesearch
        self.running = False
        self.sock: socket.socket | None = None
        self._blacklist_cache: List[str] = []
        self._last_dns_notif: dict[str, float] = {}

    def notify_dns_blocked(self, domain: str):
        """Phát thông báo ra ngoài màn hình Windows khi tên miền web bị chặn."""
        if self.enforcer and hasattr(self.enforcer, "notify_dns_blocked"):
            self.enforcer.notify_dns_blocked(domain)
            return

        now = time.time()
        last_t = self._last_dns_notif.get(domain, 0.0)
        if now - last_t < 8.0:
            return
        self._last_dns_notif[domain] = now

        title = "🌐 ChildGuard — Trang web bị hạn chế"
        msg = f"Trang web '{domain}' đã bị chặn truy cập để bảo vệ an toàn cho em theo quy định của gia đình."
        notif = {
            "title": title,
            "message": msg,
            "level": "dns_blocked",
            "subject": domain,
        }

        if self.notifier:
            try:
                self.notifier(notif)
            except Exception:
                pass
        else:
            try:
                from enforcer import show_windows_popup
                show_windows_popup(title, msg, level="dns_blocked")
            except Exception:
                pass

    def sync_policy_rules(self, policy: dict | None = None):
        """Đồng bộ danh sách cấm tên miền từ Policy vào bộ nhớ và file Hosts."""
        if policy is None:
            policy = self.storage.get_policy()

        domain_rules = policy.get("domain_rules", {})
        raw_list = domain_rules.get("blacklist", []) if isinstance(domain_rules, dict) else (domain_rules if isinstance(domain_rules, list) else [])
        self.enforce_safesearch = domain_rules.get("safesearch", True) if isinstance(domain_rules, dict) else True

        # Ở chế độ degraded safe-mode khi mất mạng dài ngày -> tự bổ sung các web giải trí
        if self.storage.check_connection_grace_period() == "degraded":
            raw_list = list(raw_list) + ["facebook.com", "tiktok.com", "youtube.com"]

        # Lọc bỏ tên miền thuộc Danh sách Miễn chặn Vĩnh viễn (NT6)
        self._blacklist_cache = [
            normalize_domain(d) for d in raw_list
            if normalize_domain(d) and not is_bypass_domain(d)
        ]

        # Áp dụng vào Windows Hosts (kèm cưỡng chế SafeSearch)
        HostsBlocker.apply_blacklist(self._blacklist_cache, enforce_safesearch=self.enforce_safesearch)

    def is_domain_blocked(self, domain: str) -> bool:
        """Kiểm tra tên miền có bị chặn hay không.

        Tuân thủ tuyệt đối: Danh sách Miễn chặn Vĩnh viễn (NT6) không bao giờ bị chặn.
        """
        norm_domain = normalize_domain(domain)
        if not norm_domain:
            return False

        # NT6: Miễn chặn vĩnh viễn
        if is_bypass_domain(norm_domain):
            return False

        if not self._blacklist_cache:
            return False

        for blocked in self._blacklist_cache:
            if not blocked:
                continue
            if norm_domain == blocked or norm_domain.endswith("." + blocked):
                return True
            if blocked.startswith("www.") and norm_domain == blocked[4:]:
                return True
            if not blocked.startswith("www.") and norm_domain == f"www.{blocked}":
                return True
        return False

    def handle_query(self, data: bytes, client_addr: tuple):
        try:
            if len(data) < 12:
                return

            domain, qname_end = parse_dns_domain(data)
            subject_domain = normalize_domain_subject(domain)
            if subject_domain:
                policy = self.storage.get_policy()
                self.storage.add_event(
                    type="domain_query",
                    subject=subject_domain,
                    policy_version=policy.get("version"),
                )

            # 1. Danh sách Miễn chặn Vĩnh viễn (NT6) -> Forward ngay tới upstream DNS
            if is_bypass_domain(domain):
                self._forward_query(data, client_addr)
                return

            # 2. Kiểm tra tên miền có bị phụ huynh chặn hay không
            if self.is_domain_blocked(domain):
                print(f"[DNS Proxy] 🚫 CHẶN TÊN MIỀN: {domain} -> Trả về 0.0.0.0 / NXDOMAIN")
                resp = build_blocked_response(data, qname_end)
                self.sock.sendto(resp, client_addr)
                # Ghi nhận lần chặn thực tế bằng tên miền đăng ký, không lưu QNAME/URL đầy đủ.
                policy = self.storage.get_policy()
                self.storage.add_event(
                    type="blocked_domain",
                    subject=subject_domain,
                    duration_sec=0,
                    policy_version=policy.get("version"),
                )
                # Thông báo ra ngoài màn hình Windows cho bé
                self.notify_dns_blocked(subject_domain)
                return

            # 3. Cưỡng chế SafeSearch (F2 - Google, Bing, YouTube)
            if self.enforce_safesearch:
                target = get_safesearch_target(domain)
                if target:
                    print(f"[DNS Proxy] 🛡️ ÁP DỤNG SAFESEARCH: {domain} -> {target['service']} ({target['ipv4']})")
                    resp = build_safesearch_response(data, qname_end, target)
                    self.sock.sendto(resp, client_addr)
                    return

            # 4. Tên miền thông thường -> Forward sang Upstream DNS (8.8.8.8)
            self._forward_query(data, client_addr)
        except Exception:
            pass

    def _forward_query(self, data: bytes, client_addr: tuple):
        """Chuyển tiếp truy vấn DNS tới Upstream DNS Server (8.8.8.8)."""
        up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up_sock.settimeout(3.0)
        try:
            up_sock.sendto(data, (self.upstream_dns, 53))
            up_resp, _ = up_sock.recvfrom(4096)
            if self.sock:
                self.sock.sendto(up_resp, client_addr)
        except Exception:
            pass
        finally:
            up_sock.close()

    def start(self):
        self.running = True
        # Khởi tạo danh sách cấm từ cached policy
        self.sync_policy_rules()

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            print(f"[DNS Proxy] Lắng nghe tại UDP {self.host}:{self.port} (Upstream: {self.upstream_dns})")
        except OSError as e:
            print(f"[DNS Proxy] Cảnh báo: Không bind được cổng {self.port} (cần quyền Admin hoặc cổng đã được dùng): {e}")
            print("[DNS Proxy] Chức năng chặn web & SafeSearch qua file Windows Hosts vẫn đang bảo vệ bình thường!")
            return

        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                t = threading.Thread(target=self.handle_query, args=(data, addr), daemon=True)
                t.start()
            except Exception:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        # Dọn dẹp sạch file hosts khi dừng agent
        HostsBlocker.clear()
        print("[DNS Proxy] Đã khôi phục file hosts về trạng thái ban đầu.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ChildGuard DNS Proxy & Windows Hosts Helper")
    parser.add_argument("--setup-hosts", action="store_true", help="Cấp quyền ghi file hosts cho Users (yêu cầu Admin hoặc UAC)")
    parser.add_argument("--test-block", nargs="+", help="Thử chặn danh sách tên miền vào file hosts")
    parser.add_argument("--clear-hosts", action="store_true", help="Xóa các quy tắc chặn của ChildGuard trong file hosts")
    parser.add_argument("--check-safesearch", type=str, help="Kiểm tra tên miền có thuộc diện SafeSearch hay không")
    parser.add_argument("--check-bypass", type=str, help="Kiểm tra tên miền có thuộc Danh sách Miễn chặn Vĩnh viễn (NT6) không")
    cli_args = parser.parse_args()

    if cli_args.setup_hosts:
        if not HostsBlocker.is_admin():
            print("[Hosts Blocker] Đang yêu cầu quyền Administrator qua UAC để cấp quyền file hosts...")
            hosts_p = HostsBlocker.get_hosts_path()
            current_c = hosts_p.read_text(encoding="utf-8", errors="ignore") if hosts_p.exists() else ""
            ok = HostsBlocker._elevated_write_windows(hosts_p, current_c)
        else:
            ok = HostsBlocker.setup_permissions()
        if ok:
            print("✓ Đã thiết lập quyền ghi file hosts cho nhóm Users thành công.")
        else:
            print("❌ Không thể thiết lập quyền file hosts.")
    elif cli_args.test_block:
        HostsBlocker.apply_blacklist(cli_args.test_block)
    elif cli_args.clear_hosts:
        HostsBlocker.clear()
    elif cli_args.check_safesearch:
        res = get_safesearch_target(cli_args.check_safesearch)
        if res:
            print(f"✓ '{cli_args.check_safesearch}' kích hoạt: {res['service']} -> IP: {res['ipv4']}, CNAME: {res['cname']}")
        else:
            print(f"✗ '{cli_args.check_safesearch}' KHÔNG thuộc diện SafeSearch.")
    elif cli_args.check_bypass:
        is_bp = is_bypass_domain(cli_args.check_bypass)
        if is_bp:
            print(f"✓ '{cli_args.check_bypass}' thuộc Danh sách Miễn chặn Vĩnh viễn (NT6).")
        else:
            print(f"✗ '{cli_args.check_bypass}' không thuộc danh sách miễn chặn.")
