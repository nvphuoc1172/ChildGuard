"""Kênh IPC (Inter-Process Communication) giữa Agent Service và Tray UI — xem mục 3 trong Design.md.

Chạy máy chủ HTTP cục bộ tại 127.0.0.1:48123 (chỉ cho phép kết nối nội bộ):
- GET /status: Cung cấp thời gian còn lại, quota, trạng thái khóa và policy minh bạch.
- POST /request: Tiếp nhận yêu cầu xin thêm giờ từ trẻ và chuyển lên Server.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from enforcer import PolicyEnforcer
    from storage import AgentStorage
    from sync import SyncWorker


class IPCHandler(BaseHTTPRequestHandler):
    storage: "AgentStorage" = None
    enforcer: "PolicyEnforcer" = None
    sync_worker: "SyncWorker" = None

    def log_message(self, format, *args):
        # Tắt bớt log HTTP cục bộ
        pass

    def do_GET(self):
        if self.path == "/status":
            policy = self.storage.get_policy()
            quota = policy.get("quota", {})
            daily_quota = quota.get("daily_minutes", 120)
            used_seconds = self.storage.get_screen_time_today()
            used_minutes = round(used_seconds / 60, 1)
            remaining_minutes = max(0, round(daily_quota - used_minutes, 1))

            status_data = {
                "daily_quota": daily_quota,
                "used_minutes": used_minutes,
                "remaining_minutes": remaining_minutes,
                "is_locked": self.storage.get_lock_status(),
                "policy": policy,
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(status_data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/request":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            try:
                data = json.loads(body)
                minutes = data.get("minutes", 15)
                reason = data.get("reason", "")

                # Gửi request lên server qua sync_worker
                if self.sync_worker:
                    res = self.sync_worker._http_request(
                        "/requests",
                        method="POST",
                        body={
                            "request_type": "grant_time",
                            "subject": str(minutes),
                            "reason": reason,
                        },
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ok", "request_id": res.get("id")}).encode("utf-8"))
                    return
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
                return

        self.send_response(404)
        self.end_headers()


class IPCServer:
    def __init__(self, storage: "AgentStorage", enforcer: "PolicyEnforcer", sync_worker: "SyncWorker", port: int = 48123):
        self.port = port
        IPCHandler.storage = storage
        IPCHandler.enforcer = enforcer
        IPCHandler.sync_worker = sync_worker
        self.server = HTTPServer(("127.0.0.1", self.port), IPCHandler)

    def start(self):
        print(f"[IPC] Lắng nghe IPC Server tại 127.0.0.1:{self.port} cho Tray UI...")
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()
