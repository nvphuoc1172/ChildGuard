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

            is_idle = getattr(self.enforcer, "is_idle", False) if self.enforcer else False
            idle_seconds = getattr(self.enforcer, "current_idle_seconds", 0.0) if self.enforcer else 0.0
            workstation_locked = getattr(self.enforcer, "is_locked_screen", False) if self.enforcer else False
            # Giữ hai trường tương thích cho Tray UI cũ; tính năng ân hạn đã bị loại bỏ.
            in_grace_period = False
            grace_seconds_left = 0
            active_notification = getattr(self.enforcer, "active_notification", None) if self.enforcer else None
            effective_rem_sec = getattr(self.enforcer, "effective_remaining_seconds", 0) if self.enforcer else 0
            effective_res_type = getattr(self.enforcer, "effective_restriction_type", "none") if self.enforcer else "none"
            dns_proxy = getattr(self.sync_worker, "dns_proxy", None) if self.sync_worker else None

            app_rules = policy.get("app_rules", {})
            raw_restricted_apps = (
                app_rules.get("blacklist", [])
                if isinstance(app_rules, dict)
                else app_rules if isinstance(app_rules, list) else []
            )
            restricted_apps = []
            for item in raw_restricted_apps:
                if isinstance(item, dict):
                    display_name = item.get("name") or item.get("sha256")
                else:
                    display_name = str(item)
                if display_name and display_name not in restricted_apps:
                    restricted_apps.append(display_name)

            from datetime import datetime
            cur_h = datetime.now().hour
            morning_m = 0.0
            afternoon_m = 0.0
            evening_m = 0.0
            if cur_h < 12:
                morning_m = used_minutes
            elif cur_h < 18:
                morning_m = min(used_minutes, 60.0)
                afternoon_m = round(max(0.0, used_minutes - morning_m), 1)
            else:
                morning_m = min(used_minutes, 60.0)
                afternoon_m = min(round(max(0.0, used_minutes - morning_m), 1), 60.0)
                evening_m = round(max(0.0, used_minutes - morning_m - afternoon_m), 1)

            status_data = {
                "daily_quota": daily_quota,
                "used_minutes": used_minutes,
                "used_seconds": used_seconds,
                "remaining_minutes": remaining_minutes,
                "is_locked": self.storage.get_lock_status(),
                "is_idle": is_idle,
                "idle_seconds": round(idle_seconds, 1),
                "workstation_locked": workstation_locked,
                "in_grace_period": in_grace_period,
                "grace_seconds_left": grace_seconds_left,
                "active_notification": active_notification,
                "effective_remaining_seconds": effective_rem_sec,
                "effective_restriction_type": effective_res_type,
                "restricted_apps": restricted_apps,
                "pending_event_count": len(self.storage.get_pending_events()),
                "last_event_sync_at": getattr(self.sync_worker, "last_event_sync_at", None),
                "last_event_sync_error": getattr(self.sync_worker, "last_event_sync_error", None),
                "recent_agent_events": self.storage.get_recent_events(limit=20),
                "dns_diagnostics": {
                    "running": bool(getattr(dns_proxy, "running", False)),
                    "routing_active": bool(getattr(dns_proxy, "_dns_routing_active", False)),
                    "listen_address": (
                        f"{getattr(dns_proxy, 'host', '127.0.0.1')}:"
                        f"{getattr(dns_proxy, 'port', 53)}"
                    ),
                },
                "policy": policy,
                "time_blocks": {
                    "morning_minutes": morning_m,
                    "afternoon_minutes": afternoon_m,
                    "evening_minutes": evening_m,
                },
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(status_data).encode("utf-8"))
        elif self.path == "/notifications":
            history = getattr(self.enforcer, "notification_history", []) if self.enforcer else []
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"notifications": history}).encode("utf-8"))
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
