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
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import websockets

from enforcer import PolicyEnforcer
from storage import AgentStorage

EVENT_FLUSH_INTERVAL_SECONDS = 5


class SyncWorker:
    def __init__(
        self,
        storage: AgentStorage,
        enforcer: PolicyEnforcer,
        state_config: dict,
        ca_cert_path: str,
        dns_proxy=None,
    ):
        self.storage = storage
        self.enforcer = enforcer
        self.dns_proxy = dns_proxy
        self.server = state_config["server"]
        self.port = state_config.get("port", 8443)
        self.device_id = state_config["device_id"]
        self.access_token = state_config["access_token"]
        self.refresh_token = state_config.get("refresh_token")
        self.access_expires_at = state_config.get("access_expires_at")
        self.state_path = Path(state_config.get("_state_path", Path(__file__).resolve().parent / "agent_state" / "device_token.json"))
        self._token_lock = threading.RLock()
        self._refresh_lock = threading.Lock()
        self._event_flush_lock = threading.Lock()
        self._stop_event = threading.Event()
        self.last_event_sync_at: str | None = None
        self.last_event_sync_error: str | None = None
        self.ca_cert_path = ca_cert_path
        self.use_http = state_config.get("use_http", False)
        self.running = False

    def _get_ssl_context(self) -> ssl.SSLContext | None:
        if self.use_http:
            return None
        if self.ca_cert_path and Path(self.ca_cert_path).exists():
            return ssl.create_default_context(cafile=self.ca_cert_path)
        return ssl._create_unverified_context()

    def _http_request(self, path: str, method: str = "GET", body: dict | None = None, is_retry: bool = False) -> dict:
        scheme = "http" if self.use_http else "https"
        url = f"{scheme}://{self.server}:{self.port}{path}"
        data_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        with self._token_lock:
            access_token = self.access_token
        headers = {"Authorization": f"Bearer {access_token}"}
        if data_bytes is not None:
            headers["Content-Type"] = "application/json"

        ctx = self._get_ssl_context()
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # Nếu gặp HTTP 401/403 và chưa retry, tự động Refresh Token và thử lại 1 lần duy nhất
            if e.code in (401, 403) and not is_retry:
                if self._refresh_access_token():
                    return self._http_request(path, method, body, is_retry=True)
                print(f"[Sync] CẢNH BÁO: Token bị từ chối (HTTP {e.code}). Có thể Server đã bị reset dữ liệu.")
                
            raise e

    def send_heartbeat(self) -> dict:
        policy = self.storage.get_policy()
        policy_version = policy.get("version", 0)
        used_seconds = self.storage.get_screen_time_today()
        pending_events = self.storage.get_pending_events()

        body = {
            "policy_version": policy_version,
            "quota_used_seconds": used_seconds,
            "queued_event_count": len(pending_events),
        }
        res = self._http_request("/heartbeat", method="POST", body=body)
        self.storage.update_server_contact()
        if res.get("server_timestamp") is not None:
            self.storage.sync_server_time(res["server_timestamp"])
        return res

    def fetch_and_apply_policy(self):
        print("[Sync] Đang đồng bộ chính sách từ server GET /policy...")
        policy_data = self._http_request("/policy", method="GET")
        self.storage.save_policy(policy_data)
        print(f"[Sync] Đã cập nhật chính sách phiên bản v{policy_data.get('version')} thành công.")
        if self.dns_proxy:
            self.dns_proxy.sync_policy_rules(policy_data)

    def flush_events_batch(self):
        with self._event_flush_lock:
            return self._flush_events_batch_locked()

    def _flush_events_batch_locked(self):
        events = self.storage.get_pending_events(limit=100)
        if not events:
            self.last_event_sync_error = None
            return 0

        payload_events = [
            {
                "idempotency_key": ev["idempotency_key"],
                "type": ev["type"],
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
            self.last_event_sync_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            self.last_event_sync_error = None
            print(f"[Sync] Đã gửi {res.get('processed')} sự kiện lên server (bỏ qua {res.get('ignored')} trùng).")
            return len(event_ids)
        except Exception as e:
            self.last_event_sync_error = str(e)
            print(f"[Sync] Chưa gửi được batch events: {e}")
            return 0

    def run_event_flush_loop(self, interval: int = EVENT_FLUSH_INTERVAL_SECONDS):
        """Upload events independently so heartbeat/policy errors cannot stall logs."""
        print(f"[Sync Events] Bắt đầu đồng bộ event độc lập mỗi {interval}s.")
        while self.running:
            self.flush_events_batch()
            self._stop_event.wait(interval)

    def execute_command(self, cmd_id: str, cmd_type: str, payload: dict):
        print(f"[Sync] ⚡ THỰC THI LỆNH KHẨN: {cmd_type} (id={cmd_id}, payload={payload})")
        if cmd_type == "lock":
            self.enforcer.lock_workstation(manual=True)
        elif cmd_type == "unlock":
            self.enforcer.unlock_workstation()
        elif cmd_type == "grant_minutes":
            mins = payload.get("minutes", 15)
            self.enforcer.grant_extra_minutes(mins)
        elif cmd_type in ("clear_data", "clear_child_data"):
            print(f"[Sync] 🧹 NHẬN LỆNH XÓA TOÀN BỘ BỘ ĐỆM DỮ LIỆU CỦA TRẺ (id={cmd_id})")
            if hasattr(self.enforcer, "reset_usage_cache"):
                self.enforcer.reset_usage_cache()
            elif hasattr(self.storage, "clear_all_cached_data"):
                self.storage.clear_all_cached_data()

        # Gửi ACK về server
        try:
            self._http_request(f"/commands/{cmd_id}/ack", method="POST", body={"status": "ok"})
            print(f"[Sync] Đã gửi ACK cho lệnh {cmd_id}.")
        except Exception as e:
            print(f"[Sync] Gửi ACK thất bại: {e}")

    def _refresh_access_token(self) -> bool:
        """Đọc refresh_token từ cấu hình, gọi API để lấy access_token mới và ghi đè file."""
        with self._refresh_lock:
            return self._refresh_access_token_locked()

    def _refresh_access_token_locked(self) -> bool:
        """Phần thực thi được serialize để heartbeat và WebSocket không refresh đè nhau."""
        print("[Sync] ⚠️ Access Token hết hạn, đang tự động làm mới (Refresh Token)...")
        try:
            if not self.state_path.exists():
                return False

            with self._token_lock, open(self.state_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            refresh_token = config.get("refresh_token")
            if not refresh_token:
                print("[Sync] Lỗi: Không tìm thấy refresh_token trong cấu hình.")
                return False

            scheme = "http" if self.use_http else "https"
            url = f"{scheme}://{self.server}:{self.port}/auth/refresh"
            headers = {
                "Authorization": f"Bearer {refresh_token}",
                "Content-Type": "application/json"
            }
            req = urllib.request.Request(url, headers=headers, method="POST")
            ctx = self._get_ssl_context()
            
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                new_access = res_data.get("access_token")
                
                if new_access:
                    with self._token_lock:
                        self.access_token = new_access
                        self.access_expires_at = res_data.get("access_expires_at")
                        config["access_token"] = new_access
                        config["access_expires_at"] = self.access_expires_at
                        # Ghi atomically để mất điện không làm hỏng file token.
                        tmp_path = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
                        tmp_path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
                        tmp_path.replace(self.state_path)
                        
                    print("[Sync] ✓ Đã làm mới Access Token thành công. Khôi phục kết nối.")
                    return True
        except Exception as e:
            print(f"[Sync] ❌ Cấp lại token thất bại: {e}")
            
        return False

    def _access_token_needs_refresh(self, margin_seconds: int = 120) -> bool:
        if not self.access_expires_at:
            return True
        try:
            expiry = datetime.fromisoformat(self.access_expires_at.rstrip("Z")).replace(tzinfo=timezone.utc)
            return (expiry - datetime.now(timezone.utc)).total_seconds() <= margin_seconds
        except (TypeError, ValueError):
            return True
    
    async def _websocket_loop(self):
        """Vòng lặp WebSocket thời gian thực (<5s latency)."""
        ws_scheme = "ws" if self.use_http else "wss"
        ssl_ctx = self._get_ssl_context()

        while self.running:
            try:
                if self._access_token_needs_refresh():
                    self._refresh_access_token()
                with self._token_lock:
                    ws_token = self.access_token
                ws_url = f"{ws_scheme}://{self.server}:{self.port}/ws/{self.device_id}?token={ws_token}"
                print(f"[Sync WS] Đang kết nối kênh lệnh khẩn WebSocket tới {self.server}:{self.port}...")
                async with websockets.connect(ws_url, ssl=ssl_ctx, ping_interval=20, ping_timeout=10) as ws:
                    print("[Sync WS] ✓ Kết nối WebSocket thành công. Sẵn sàng nhận lệnh khẩn cấp!")
                    self.storage.update_server_contact()

                    while self.running:
                        msg_text = await ws.recv()
                        try:
                            msg = json.loads(msg_text)
                            if msg.get("type") == "time_sync":
                                server_ts = msg.get("server_timestamp")
                                if server_ts is not None:
                                    self.storage.sync_server_time(server_ts)
                                    print(f"[Sync WS] ⏱️ Đồng bộ thời gian UTC máy chủ thành công: {msg.get('server_time')}")
                            elif "command_id" in msg and "type" in msg:
                                self.execute_command(msg["command_id"], msg["type"], msg.get("payload", {}))
                                # Phản hồi ACK ngay qua WebSocket
                                await ws.send(json.dumps({"type": "ack", "command_id": msg["command_id"]}))
                        except Exception as e:
                            print(f"[Sync WS] Lỗi xử lý message: {e}")
            except Exception as e:
                print(f"[Sync WS] Mất kết nối WebSocket ({e}). Thử lại sau 5s...")
                if self._access_token_needs_refresh():
                    self._refresh_access_token()
                await asyncio.sleep(5)

    def _run_ws_thread(self):
        asyncio.run(self._websocket_loop())

    def run_heartbeat_loop(self, interval: int = 30):
        self.running = True
        self._stop_event.clear()
        # Chỉ làm mới nếu access token thực sự gần hết hạn.
        if self._access_token_needs_refresh():
            self._refresh_access_token()

        event_thread = threading.Thread(target=self.run_event_flush_loop, daemon=True)
        event_thread.start()
        # Luôn đồng bộ chính sách mới nhất ngay khi Agent khởi chạy
        try:
            self.fetch_and_apply_policy()
        except Exception as e:
            print(f"[Sync] Chưa đồng bộ được policy khi khởi động: {e}")

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

            except Exception as e:
                print(f"[Sync] Không kết nối được tới server trong lần heartbeat: {e}")

            self._stop_event.wait(interval)

    def stop(self):
        self.running = False
        self._stop_event.set()
