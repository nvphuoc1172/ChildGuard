"""DNS Proxy 127.0.0.1:53 & Windows Hosts Filter — xem mục 3 và 10.3 trong Design.md.

Chịu trách nhiệm:
1. Đồng bộ danh sách tên miền bị cấm vào Windows Hosts (chặn triệt để cả IPv4/IPv6, mọi trình duyệt Edge/Chrome/Firefox).
2. Lắng nghe UDP query trên 127.0.0.1:53 theo chuẩn RFC 1035:
   - Type A (1) -> Trả về 0.0.0.0
   - Type AAAA (28) -> Trả về ::
   - Type khác (HTTPS/SVCB) -> Trả về NXDOMAIN (RCODE=3)
3. Ghi nhận sự kiện web_blocked vào hàng đợi SQLite offline.
4. Chuyển tiếp (forward) các truy vấn được phép tới Upstream DNS (8.8.8.8:53).
"""
from __future__ import annotations

import os
import socket
import struct
import subprocess
import sys
import threading
from pathlib import Path
from typing import List, Set, Tuple

from storage import AgentStorage

TAG_START = "# --- CHILDGUARD_MANAGED_BLOCK_START ---"
TAG_END = "# --- CHILDGUARD_MANAGED_BLOCK_END ---"


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


class HostsBlocker:
    """Quản lý file hosts của Windows để chặn tên miền cấp hệ điều hành (không thể bypass qua DNS dự phòng hay DoH)."""

    @staticmethod
    def get_hosts_path() -> Path:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        return Path(system_root) / "System32" / "drivers" / "etc" / "hosts"

    @classmethod
    def apply_blacklist(cls, raw_domains: List[str]) -> bool:
        if sys.platform != "win32":
            return True

        hosts_path = cls.get_hosts_path()
        try:
            content = ""
            if hosts_path.exists():
                content = hosts_path.read_text(encoding="utf-8", errors="ignore")

            # Xóa khối block cũ nếu đã tồn tại
            if TAG_START in content and TAG_END in content:
                before = content.split(TAG_START)[0]
                after = content.split(TAG_END)[1]
                content = before.rstrip() + "\n" + after.lstrip()

            new_block_lines = []
            if raw_domains:
                new_block_lines.append(TAG_START)
                seen_domains: Set[str] = set()

                for raw in raw_domains:
                    d = normalize_domain(raw)
                    if not d or "." not in d:
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
                        if target not in seen_domains:
                            seen_domains.add(target)
                            new_block_lines.append(f"0.0.0.0 {target}")
                            new_block_lines.append(f":: {target}")

                new_block_lines.append(TAG_END)

            if new_block_lines:
                final_content = content.rstrip() + "\n\n" + "\n".join(new_block_lines) + "\n"
            else:
                final_content = content.rstrip() + "\n"

            hosts_path.write_text(final_content, encoding="utf-8")
            # Xóa cache DNS của Windows để áp dụng tức thì
            subprocess.run("ipconfig /flushdns", shell=True, capture_output=True)
            print(f"[Hosts Blocker] ✓ Đã đồng bộ {len(raw_domains)} tên miền cấm vào file hosts.")
            return True
        except Exception as e:
            print(f"[Hosts Blocker] Cảnh báo lỗi cập nhật file hosts (cần quyền Admin): {e}")
            return False

    @classmethod
    def clear(cls) -> bool:
        return cls.apply_blacklist([])


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


class DNSProxyServer:
    def __init__(self, storage: AgentStorage, host: str = "127.0.0.1", port: int = 53, upstream_dns: str = "8.8.8.8"):
        self.storage = storage
        self.host = host
        self.port = port
        self.upstream_dns = upstream_dns
        self.running = False
        self.sock: socket.socket | None = None
        self._blacklist_cache: List[str] = []

    def sync_policy_rules(self, policy: dict | None = None):
        """Đồng bộ danh sách cấm tên miền từ Policy vào bộ nhớ và file Hosts."""
        if policy is None:
            policy = self.storage.get_policy()

        domain_rules = policy.get("domain_rules", {})
        raw_list = domain_rules.get("blacklist", [])

        # Ở chế độ degraded safe-mode khi mất mạng dài ngày -> tự bổ sung các web giải trí
        if self.storage.check_connection_grace_period() == "degraded":
            raw_list = list(raw_list) + ["facebook.com", "tiktok.com", "youtube.com"]

        self._blacklist_cache = [normalize_domain(d) for d in raw_list if normalize_domain(d)]

        # Áp dụng vào Windows Hosts
        HostsBlocker.apply_blacklist(self._blacklist_cache)

    def is_domain_blocked(self, domain: str) -> bool:
        norm_domain = normalize_domain(domain)
        if not norm_domain or not self._blacklist_cache:
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

            if self.is_domain_blocked(domain):
                print(f"[DNS Proxy] 🚫 CHẶN TÊN MIỀN: {domain} -> Trả về 0.0.0.0 / NXDOMAIN")
                resp = build_blocked_response(data, qname_end)
                self.sock.sendto(resp, client_addr)
                # Ghi nhận sự kiện web_blocked
                policy = self.storage.get_policy()
                self.storage.add_event(
                    event_type="web_blocked",
                    subject=domain,
                    duration_sec=0,
                    policy_version=policy.get("version"),
                )
            else:
                # Forward sang upstream DNS
                up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                up_sock.settimeout(3.0)
                try:
                    up_sock.sendto(data, (self.upstream_dns, 53))
                    up_resp, _ = up_sock.recvfrom(4096)
                    self.sock.sendto(up_resp, client_addr)
                finally:
                    up_sock.close()
        except Exception:
            pass

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
            print("[DNS Proxy] Chức năng chặn web qua file Windows Hosts vẫn đang bảo vệ bình thường!")
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
