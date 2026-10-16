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
import ctypes
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

from dns_proxy import DNSProxyServer, HostsBlocker
from enforcer import PolicyEnforcer
from ipc import IPCServer
from storage import AgentStorage
from sync import SyncWorker
from enroll import call_enroll, compute_fingerprint, save_state


def is_admin() -> bool:
    if sys.platform != "win32":
        return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def ensure_admin(allow_elevate: bool = True) -> bool:
    """Kiểm tra quyền Administrator và tự động kích hoạt UAC nếu cần."""
    if sys.platform != "win32":
        return True
    if is_admin():
        print("[Agent] ✓ Đang chạy với quyền Administrator.")
        return True

    print("[Agent] ⚠️ Cảnh báo: Agent đang chạy mà KHÔNG có quyền Administrator.")
    if not allow_elevate:
        print("[Agent] Chế độ bỏ qua nâng quyền (--no-elevate) được bật.")
        return False

    print("[Agent] Đang tự động yêu cầu nâng quyền qua Windows UAC để kích hoạt đầy đủ tính năng...")
    try:
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        if ret > 32:
            print("[Agent] Đã mở tiến trình Agent với quyền Administrator trong cửa sổ mới.")
            sys.exit(0)
        else:
            print("[Agent] Người dùng đã từ chối cấp quyền UAC. Tiếp tục chạy với quyền hạn chế...")
            return False
    except Exception as exc:
        print(f"[Agent] Không thể gọi UAC: {exc}. Tiếp tục chạy...")
        return False


def load_agent_state(state_path: Path) -> dict:
    if not state_path.exists():
        raise SystemExit(
            f"Không tìm thấy file cấu hình {state_path}!\n"
            f"Vui lòng chạy 'python enroll.py --server <IP> --ca-cert <cert>' trước để ghép đôi máy trẻ em."
        )
    return json.loads(state_path.read_text(encoding="utf-8"))


def enroll_from_console(state_path: Path, server: str, port: int, ca_cert: str, use_http: bool) -> dict:
    """Ghép đôi ngay trong cửa sổ Agent và thay thế an toàn phiên cũ."""
    print("\n[Agent] Nhập mã 8 ký tự được tạo trên Dashboard.")
    code = input("Mã ghép đôi: ").strip().upper()
    if len(code) != 8:
        raise ValueError("Mã ghép đôi phải có đúng 8 ký tự.")
    result = call_enroll(server, port, ca_cert, code, compute_fingerprint(), use_http=use_http)
    state = {
        "device_id": result["device_id"],
        "access_token": result["access_token"],
        "refresh_token": result["refresh_token"],
        "access_expires_at": result.get("access_expires_at"),
        "refresh_expires_at": result.get("refresh_expires_at"),
        "policy_version": result["policy_version"],
        "server": server,
        "port": port,
        "use_http": use_http,
    }
    save_state(state_path, state)
    print("[Agent] ✓ Ghép đôi thành công. Agent sẽ khởi động với phiên mới.")
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", default="agent_state/device_token.json", help="Đường dẫn file token ghép đôi")
    parser.add_argument("--ca-cert", default="certs/ogk-ca.crt", help="Đường dẫn chứng chỉ CA nội bộ")
    parser.add_argument("--dns-port", type=int, default=53, help="Cổng DNS Proxy (mặc định: 53)")
    parser.add_argument("--ipc-port", type=int, default=48123, help="Cổng IPC Server (mặc định: 48123)")
    parser.add_argument("--no-elevate", action="store_true", help="Không tự động yêu cầu quyền Administrator qua UAC")
    parser.add_argument("--server", default="127.0.0.1", help="Server dùng ở lần ghép đôi đầu tiên")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--http", action="store_true", help="HTTP chỉ dành cho môi trường dev")
    parser.add_argument("--dev-safe-lock", action="store_true", help="Chỉ gọi khóa Windows một lần cho mỗi đợt khóa khi test cùng máy")
    parser.add_argument("--pair", action="store_true", help="Nhập mã ghép đôi mới trước khi chạy Agent")
    parser.add_argument("--no-tray", action="store_true", help="Không tự động khởi chạy Tray UI khay hệ thống")
    args = parser.parse_args()

    state_file = Path(args.state)
    ca_cert_path = str(Path(args.ca_cert).resolve())

    print("=" * 60)
    print("  🛡️  OGK-AGENT (CHILDGUARD) — DỊCH VỤ BẢO VỆ MÁY TRẺ EM")
    print("=" * 60)

    # 0. Kiểm tra quyền Administrator và thiết lập quyền file hosts
    ensure_admin(allow_elevate=not args.no_elevate)
    HostsBlocker.setup_permissions()

    if state_file.exists():
        if args.pair:
            old = load_agent_state(state_file)
            config = enroll_from_console(
                state_file, old.get("server", args.server), old.get("port", args.port),
                ca_cert_path, old.get("use_http", args.http),
            )
        else:
            config = load_agent_state(state_file)
    else:
        print("[Agent] Chưa ghép đôi. Có thể nhập mã ngay tại đây, không cần chạy enroll.py.")
        config = enroll_from_console(state_file, args.server, args.port, ca_cert_path, args.http)
    config["_state_path"] = str(state_file.resolve())
    print(f"[Agent] Thiết bị ID: {config['device_id']}")
    print(f"[Agent] Máy chủ điều phối: {config['server']}:{config.get('port', 8443)}")

    # 1. Khởi tạo Storage cục bộ (SQLite)
    storage = AgentStorage()
    print("[Agent] ✓ Đã khởi tạo kho lưu trữ cục bộ SQLite (agent_state/agent.db)")

    # 2. Khởi tạo Policy Enforcer
    enforcer = PolicyEnforcer(storage, safe_lock_once=args.dev_safe_lock)
    enforcer_thread = threading.Thread(target=enforcer.run_loop, daemon=True)
    enforcer_thread.start()
    print("[Agent] ✓ Policy Enforcer đã chạy (Quét App & Đếm thời gian sử dụng)")

    # 3. Khởi tạo DNS Proxy Server (liên kết với enforcer để phát thông báo khi chặn web)
    dns_proxy = DNSProxyServer(storage, port=args.dns_port, enforcer=enforcer)
    dns_thread = threading.Thread(target=dns_proxy.start, daemon=True)
    dns_thread.start()

    # 4. Khởi tạo Sync Worker (WebSocket + Heartbeat)
    sync_worker = SyncWorker(storage, enforcer, config, ca_cert_path, dns_proxy=dns_proxy)
    sync_thread = threading.Thread(target=sync_worker.run_heartbeat_loop, daemon=True)
    sync_thread.start()
    print("[Agent] ✓ Sync Worker đã chạy (WebSocket lệnh khẩn <5s & Heartbeat)")

    # 5. Khởi tạo IPC Server cho Tray UI
    ipc_server = IPCServer(storage, enforcer, sync_worker, port=args.ipc_port)
    ipc_thread = threading.Thread(target=ipc_server.start, daemon=True)
    ipc_thread.start()
    print(f"[Agent] ✓ Local IPC Server đã mở tại 127.0.0.1:{args.ipc_port}")

    # 6. Khởi chạy Tray UI song song trong cùng phiên Agent
    tray_app = None
    if not args.no_tray:
        try:
            from tray.tray_app import TrayApp
            tray_app = TrayApp(ipc_url=f"http://127.0.0.1:{args.ipc_port}")
            tray_thread = threading.Thread(target=tray_app.run, daemon=True)
            tray_thread.start()
            print("[Agent] ✓ Đã khởi chạy đồng thời Tray UI (Giao diện khay hệ thống)")
        except Exception as e:
            print(f"[Agent] Không thể khởi chạy Tray UI tự động: {e}")

    print()
    print("[Agent] Dịch vụ đang hoạt động bình thường. Nhấn Ctrl+C để dừng.")
    if args.dev_safe_lock:
        print("[Agent] ⚠ DEV SAFE LOCK: mỗi đợt chính sách chỉ gọi khóa Windows một lần.")
    print("=" * 60)

    def shutdown(sig, frame):
        print("\n[Agent] Đang dừng an toàn các tiến trình...")
        if tray_app:
            try:
                tray_app.stop()
            except Exception:
                pass
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
