"""OGK-Agent — Điểm khởi chạy toàn bộ dịch vụ Agent trên Windows.

Điều phối đồng thời 4 thành phần cốt lõi:
1. Policy Enforcer & Screen-time Counter (chặn app, đếm giờ, khóa máy).
2. DNS Proxy 127.0.0.1:53 (chặn tên miền web đen, chuyển tiếp upstream).
3. Sync Worker (kết nối WebSocket nhận lệnh tức thì <5s, Heartbeat 60s, Batch Events).
4. Local IPC Server (giao tiếp với Tray UI qua 127.0.0.1:48123).

Chạy thử:
    python run_agent.py --ca-cert certs\\ogk-ca.crt
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import time
from pathlib import Path

from dns_proxy import DNSProxyServer
from enforcer import PolicyEnforcer
from ipc import IPCServer
from storage import AgentStorage
from sync import SyncWorker


def load_agent_state(state_path: Path) -> dict:
    if not state_path.exists():
        raise SystemExit(
            f"Không tìm thấy file cấu hình {state_path}!\n"
            f"Vui lòng chạy 'python enroll.py --server <IP> --ca-cert <cert>' trước để ghép đôi máy trẻ em."
        )
    return json.loads(state_path.read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", default="agent_state/device_token.json", help="Đường dẫn file token ghép đôi")
    parser.add_argument("--ca-cert", default="certs/ogk-ca.crt", help="Đường dẫn chứng chỉ CA nội bộ")
    parser.add_argument("--dns-port", type=int, default=53, help="Cổng DNS Proxy (mặc định: 53)")
    parser.add_argument("--ipc-port", type=int, default=48123, help="Cổng IPC Server (mặc định: 48123)")
    args = parser.parse_args()

    state_file = Path(args.state)
    ca_cert_path = str(Path(args.ca_cert).resolve())

    print("=" * 60)
    print("  🛡️  OGK-AGENT (CHILDGUARD) — DỊCH VỤ BẢO VỆ MÁY TRẺ EM")
    print("=" * 60)

    config = load_agent_state(state_file)
    print(f"[Agent] Thiết bị ID: {config['device_id']}")
    print(f"[Agent] Máy chủ điều phối: {config['server']}:{config.get('port', 8443)}")

    # 1. Khởi tạo Storage cục bộ (SQLite)
    storage = AgentStorage()
    print("[Agent] ✓ Đã khởi tạo kho lưu trữ cục bộ SQLite (agent_state/agent.db)")

    # 2. Khởi tạo Policy Enforcer
    enforcer = PolicyEnforcer(storage)
    enforcer_thread = threading.Thread(target=enforcer.run_loop, daemon=True)
    enforcer_thread.start()
    print("[Agent] ✓ Policy Enforcer đã chạy (Quét App & Đếm thời gian sử dụng)")

    # 3. Khởi tạo DNS Proxy Server
    dns_proxy = DNSProxyServer(storage, port=args.dns_port)
    dns_thread = threading.Thread(target=dns_proxy.start, daemon=True)
    dns_thread.start()

    # 4. Khởi tạo Sync Worker (WebSocket + Heartbeat)
    sync_worker = SyncWorker(storage, enforcer, config, ca_cert_path)
    sync_thread = threading.Thread(target=sync_worker.run_heartbeat_loop, daemon=True)
    sync_thread.start()
    print("[Agent] ✓ Sync Worker đã chạy (WebSocket lệnh khẩn <5s & Heartbeat)")

    # 5. Khởi tạo IPC Server cho Tray UI
    ipc_server = IPCServer(storage, enforcer, sync_worker, port=args.ipc_port)
    ipc_thread = threading.Thread(target=ipc_server.start, daemon=True)
    ipc_thread.start()
    print(f"[Agent] ✓ Local IPC Server đã mở tại 127.0.0.1:{args.ipc_port}")

    print()
    print("[Agent] Dịch vụ đang hoạt động bình thường. Nhấn Ctrl+C để dừng.")
    print("=" * 60)

    def shutdown(sig, frame):
        print("\n[Agent] Đang dừng an toàn các tiến trình...")
        enforcer.stop()
        dns_proxy.stop()
        sync_worker.stop()
        ipc_server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
