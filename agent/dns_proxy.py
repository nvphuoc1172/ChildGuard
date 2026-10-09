"""DNS Proxy 127.0.0.1:53 — xem mục 3 và 10.3 trong Design.md.

Chịu trách nhiệm:
1. Lắng nghe UDP query trên 127.0.0.1:53.
2. Trích xuất tên miền truy vấn (DNS question QNAME).
3. So khớp với domain blacklist trong chính sách (cached_policy).
4. Nếu bị cấm -> Trả IP 0.0.0.0 và ghi sự kiện web_blocked vào hàng đợi.
5. Nếu được phép -> Forward tới upstream DNS (8.8.8.8:53) và trả kết quả về cho client.
"""
from __future__ import annotations

import socket
import struct
import subprocess
import threading
from typing import Tuple

from storage import AgentStorage


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
    """Tạo gói DNS Response trả về IP 0.0.0.0 cho domain bị chặn."""
    tx_id = query_data[:2]
    flags = b"\x81\x80"  # Standard query response, No error
    qdcount = b"\x00\x01"
    ancount = b"\x00\x01"  # 1 Answer
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = tx_id + flags + qdcount + ancount + nscount + arcount

    question = query_data[12 : qname_end + 4]  # Question section (qname + qtype + qclass)

    # Answer: Type A, Class IN, TTL 300s, IP 0.0.0.0
    ans_name = b"\xc0\x0c"  # con trỏ nén trỏ tới byte 12
    ans_type = b"\x00\x01"  # Type A
    ans_class = b"\x00\x01"  # Class IN
    ans_ttl = struct.pack(">I", 300)
    ans_rdlen = b"\x00\x04"
    ans_rdata = b"\x00\x00\x00\x00"  # 0.0.0.0
    answer = ans_name + ans_type + ans_class + ans_ttl + ans_rdlen + ans_rdata

    return header + question + answer


class DNSProxyServer:
    def __init__(self, storage: AgentStorage, host: str = "127.0.0.1", port: int = 53, upstream_dns: str = "8.8.8.8"):
        self.storage = storage
        self.host = host
        self.port = port
        self.upstream_dns = upstream_dns
        self.running = False
        self.sock: socket.socket | None = None

    def is_domain_blocked(self, domain: str, policy: dict) -> bool:
        domain_rules = policy.get("domain_rules", {})
        blacklist = [d.lower().strip() for d in domain_rules.get("blacklist", []) if d.strip()]
        if not blacklist:
            return False

        for blocked in blacklist:
            if domain == blocked or domain.endswith("." + blocked):
                return True
        return False

    def handle_query(self, data: bytes, client_addr: tuple):
        try:
            if len(data) < 12:
                return

            domain, qname_end = parse_dns_domain(data)
            policy = self.storage.get_policy()

            # Chế độ degraded safe-mode khi mất mạng dài ngày: chặn mọi web giải trí
            if self.storage.check_connection_grace_period() == "degraded":
                policy["domain_rules"].setdefault("blacklist", []).extend(["facebook.com", "tiktok.com", "youtube.com"])

            if self.is_domain_blocked(domain, policy):
                print(f"[DNS Proxy] 🚫 CHẶN TÊN MIỀN: {domain} -> Trả về 0.0.0.0")
                resp = build_blocked_response(data, qname_end)
                self.sock.sendto(resp, client_addr)
                # Ghi nhận sự kiện web_blocked
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
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            print(f"[DNS Proxy] Lắng nghe tại UDP {self.host}:{self.port} (Upstream: {self.upstream_dns})")
        except OSError as e:
            print(f"[DNS Proxy] Cảnh báo: Không bind được cổng {self.port} (cần quyền Admin hoặc cổng đã được dùng): {e}")
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


def set_windows_dns(dns_ip: str = "127.0.0.1"):
    """Cấu hình DNS của Windows trỏ về 127.0.0.1."""
    cmd = f'powershell -Command "Get-NetAdapter | Where-Object Status -eq Up | Set-DnsClientServerAddress -ServerAddresses (\'{dns_ip}\')"'
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"[DNS Helper] Đã cấu hình DNS adapter về {dns_ip}")
    except Exception as e:
        print(f"[DNS Helper] Lỗi cấu hình DNS: {e}")


def reset_windows_dns_dhcp():
    """Khôi phục DNS của Windows về DHCP."""
    cmd = 'powershell -Command "Get-NetAdapter | Where-Object Status -eq Up | Set-DnsClientServerAddress -ResetServerAddresses"'
    try:
        subprocess.run(cmd, shell=True, check=True)
        print("[DNS Helper] Đã khôi phục DNS adapter về DHCP")
    except Exception as e:
        print(f"[DNS Helper] Lỗi khôi phục DNS: {e}")
