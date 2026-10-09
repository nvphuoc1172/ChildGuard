"""Sync Worker & WebSocket Client — xem mục 5.2 và 5.3 trong Design.md.

Chịu trách nhiệm:
1. Duy trì kết nối WebSocket thời gian thực (WSS) để nhận lệnh khẩn cấp tức thì (<5s).
2. Vòng lặp Heartbeat 60s (kênh dự phòng đảm bảo tính sẵn sàng).
3. Tự động đồng bộ lô sự kiện từ hàng đợi SQLite lên Server qua POST /events/batch.
4. Tải và áp dụng bản cập nhật chính sách mới (GET /policy).
"""
from __future__ import annotations

import asyncio
import json
import ssl
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import websockets

from enforcer import PolicyEnforcer
from storage import AgentStorage


class SyncWorker:
    def __init__(
        self,
        storage: AgentStorage,
        enforcer: PolicyEnforcer,
        state_config: dict,
        ca_cert_path: str,
    ):
        self.storage = storage
        self.enforcer = enforcer
        self.server = state_config["server"]
        self.port = state_config.get("port", 8443)
        self.device_id = state_config["device_id"]
        self.access_token = state_config["access_token"]
        self.ca_cert_path = ca_cert_path
        self.running = False

    def _get_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cafile=self.ca_cert_path)
        return ctx

    def _http_request(self, path: str, method: str = "GET", body: dict | None = None) -> dict:
        url = f"https://{self.server}:{self.port}{path}"
        data_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Authorization": f"Bearer {self.access_token}"}
        if data_bytes is not None:
            headers["Content-Type"] = "application/json"

        ctx = self._get_ssl_context()
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def send_heartbeat(self) -> dict:
        policy = self.storage.get_policy()
        policy_version = policy.get("version", 1)
        used_seconds = self.storage.get_screen_time_today()
        pending_events = self.storage.get_pending_events()

        body = {
            "policy_version": policy_version,
            "quota_used_seconds": used_seconds,
            "queued_event_count": len(pending_events),
        }
        res = self._http_request("/heartbeat", method="POST", body=body)
        self.storage.update_server_contact()
        return res

    def fetch_and_apply_policy(self):
        print("[Sync] Chính sách có thay đổi -> Đang lấy bản mới từ GET /policy...")
        policy_data = self._http_request("/policy", method="GET")
        self.storage.save_policy(policy_data)
        print(f"[Sync] Đã cập nhật chính sách phiên bản v{policy_data.get('version')} thành công.")

    def flush_events_batch(self):
        events = self.storage.get_pending_events(limit=100)
        if not events:
            return

        payload_events = [
            {
                "idempotency_key": ev["idempotency_key"],
                "event_type": ev["event_type"],
                "subject": ev["subject"],
                "duration_sec": ev["duration_sec"],
                "policy_version": ev["policy_version"],
                "created_at": ev["created_at"],
            }
            for ev in events
        ]

        try:
            res = self._http_request("/events/batch", method="POST", body={"events": payload_events})
            event_ids = [ev["id"] for ev in events]
            self.storage.mark_events_sent(event_ids)
            print(f"[Sync] Đã gửi {res.get('processed')} sự kiện lên server (bỏ qua {res.get('ignored')} trùng).")
        except Exception as e:
            print(f"[Sync] Chưa gửi được batch events: {e}")

    def execute_command(self, cmd_id: str, cmd_type: str, payload: dict):
        print(f"[Sync] ⚡ THỰC THI LỆNH KHẨN: {cmd_type} (id={cmd_id}, payload={payload})")
        if cmd_type == "lock":
            self.enforcer.lock_workstation()
        elif cmd_type == "unlock":
            self.enforcer.unlock_workstation()
        elif cmd_type == "grant_minutes":
            mins = payload.get("minutes", 15)
            self.enforcer.grant_extra_minutes(mins)

        # Gửi ACK về server
        try:
            self._http_request(f"/commands/{cmd_id}/ack", method="POST", body={"status": "ok"})
            print(f"[Sync] Đã gửi ACK cho lệnh {cmd_id}.")
        except Exception as e:
            print(f"[Sync] Gửi ACK thất bại: {e}")

    async def _websocket_loop(self):
        """Vòng lặp WebSocket thời gian thực (<5s latency)."""
        ws_url = f"wss://{self.server}:{self.port}/ws/{self.device_id}?token={self.access_token}"
        ssl_ctx = self._get_ssl_context()

        while self.running:
            try:
                print(f"[Sync WS] Đang kết nối kênh lệnh khẩn WebSocket tới {self.server}:{self.port}...")
                async with websockets.connect(ws_url, ssl=ssl_ctx, ping_interval=20, ping_timeout=10) as ws:
                    print("[Sync WS] ✓ Kết nối WebSocket thành công. Sẵn sàng nhận lệnh khẩn cấp!")
                    self.storage.update_server_contact()

                    while self.running:
                        msg_text = await ws.recv()
                        try:
                            msg = json.loads(msg_text)
                            if "command_id" in msg and "type" in msg:
                                self.execute_command(msg["command_id"], msg["type"], msg.get("payload", {}))
                                # Phản hồi ACK ngay qua WebSocket
                                await ws.send(json.dumps({"type": "ack", "command_id": msg["command_id"]}))
                        except Exception as e:
                            print(f"[Sync WS] Lỗi xử lý message: {e}")
            except Exception as e:
                print(f"[Sync WS] Mất kết nối WebSocket ({e}). Thử lại sau 5s...")
                await asyncio.sleep(5)

    def _run_ws_thread(self):
        asyncio.run(self._websocket_loop())

    def run_heartbeat_loop(self, interval: int = 60):
        self.running = True
        # Khởi chạy luồng WebSocket
        ws_thread = threading.Thread(target=self._run_ws_thread, daemon=True)
        ws_thread.start()

        print(f"[Sync] Bắt đầu vòng lặp Heartbeat (mỗi {interval}s)...")
        while self.running:
            try:
                # 1. Gửi Heartbeat
                res = self.send_heartbeat()
                print(f"[Sync] Heartbeat OK — policy v{res['policy_version']}, changed={res['policy_changed']}")

                # 2. Kiểm tra nếu policy đổi
                if res.get("policy_changed"):
                    self.fetch_and_apply_policy()

                # 3. Thực thi pending commands (dự phòng nếu WS bị miss)
                for cmd in res.get("pending_commands", []):
                    self.execute_command(cmd["command_id"], cmd["type"], cmd.get("payload", {}))

                # 4. Đẩy batch events
                self.flush_events_batch()

            except Exception as e:
                print(f"[Sync] Không kết nối được tới server trong lần heartbeat: {e}")

            time.sleep(interval)

    def stop(self):
        self.running = False
