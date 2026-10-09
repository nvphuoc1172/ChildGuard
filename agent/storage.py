"""Kho lưu trữ dữ liệu cục bộ của Agent (SQLite) — xem mục 3 và 5.4, 5.5 trong Design.md.

Chịu trách nhiệm:
1. Lưu bản sao chính sách gần nhất (cached_policy) để áp dụng ngay cả khi offline (Fail-closed).
2. Hàng đợi sự kiện cục bộ (event_queue) kèm idempotency_key để đồng bộ sau khi có mạng lại.
3. Quản lý trạng thái screen-time tích lũy trong ngày và chế độ degraded safe-mode.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from datetime import date, datetime
from pathlib import Path


class AgentStorage:
    def __init__(self, db_path: Path | str | None = None):
        if db_path is None:
            base_dir = Path(__file__).resolve().parent / "agent_state"
            base_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = base_dir / "agent.db"
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cached_policy (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    version INTEGER NOT NULL DEFAULT 1,
                    quota_json TEXT NOT NULL DEFAULT '{}',
                    schedule_json TEXT NOT NULL DEFAULT '{}',
                    app_rules_json TEXT NOT NULL DEFAULT '{}',
                    domain_rules_json TEXT NOT NULL DEFAULT '{}',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS event_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    idempotency_key TEXT UNIQUE NOT NULL,
                    event_type TEXT NOT NULL,
                    subject TEXT,
                    duration_sec INTEGER NOT NULL DEFAULT 0,
                    policy_version INTEGER,
                    created_at TEXT NOT NULL,
                    sent INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS agent_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    device_id TEXT,
                    current_date TEXT NOT NULL,
                    quota_used_seconds INTEGER NOT NULL DEFAULT 0,
                    is_locked INTEGER NOT NULL DEFAULT 0,
                    last_server_contact_ts REAL NOT NULL DEFAULT 0,
                    in_degraded_mode INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            # Khởi tạo bản ghi mặc định cho agent_state nếu chưa có
            today_str = date.today().isoformat()
            conn.execute(
                """
                INSERT OR IGNORE INTO agent_state (id, current_date, quota_used_seconds, is_locked, last_server_contact_ts)
                VALUES (1, ?, 0, 0, ?)
                """,
                (today_str, time.time()),
            )
            conn.commit()

    def get_policy(self) -> dict:
        """Lấy chính sách đã cache."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM cached_policy WHERE id = 1").fetchone()
            if not row:
                return {
                    "version": 1,
                    "quota": {"daily_minutes": 120},
                    "schedule": {"start_time": "07:00", "end_time": "21:30"},
                    "app_rules": {"blacklist": []},
                    "domain_rules": {"blacklist": []},
                }
            return {
                "version": row["version"],
                "quota": json.loads(row["quota_json"]),
                "schedule": json.loads(row["schedule_json"]),
                "app_rules": json.loads(row["app_rules_json"]),
                "domain_rules": json.loads(row["domain_rules_json"]),
            }

    def save_policy(self, policy_data: dict):
        """Lưu chính sách mới từ server vào cache."""
        version = policy_data.get("version", 1)
        quota_json = json.dumps(policy_data.get("quota", {}))
        schedule_json = json.dumps(policy_data.get("schedule", {}))
        app_rules_json = json.dumps(policy_data.get("app_rules", {}))
        domain_rules_json = json.dumps(policy_data.get("domain_rules", {}))
        now_str = datetime.utcnow().isoformat()

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO cached_policy (id, version, quota_json, schedule_json, app_rules_json, domain_rules_json, updated_at)
                VALUES (1, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    version = excluded.version,
                    quota_json = excluded.quota_json,
                    schedule_json = excluded.schedule_json,
                    app_rules_json = excluded.app_rules_json,
                    domain_rules_json = excluded.domain_rules_json,
                    updated_at = excluded.updated_at
                """,
                (version, quota_json, schedule_json, app_rules_json, domain_rules_json, now_str),
            )
            conn.commit()

    def add_event(self, event_type: str, subject: str | None = None, duration_sec: int = 0, policy_version: int | None = None) -> str:
        """Thêm sự kiện vào hàng đợi offline với idempotency_key duy nhất."""
        idempotency_key = f"ev_{uuid.uuid4().hex}"
        now_str = datetime.utcnow().isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO event_queue (idempotency_key, event_type, subject, duration_sec, policy_version, created_at, sent)
                VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (idempotency_key, event_type, subject, duration_sec, policy_version, now_str),
            )
            conn.commit()
        return idempotency_key

    def get_pending_events(self, limit: int = 100) -> list[dict]:
        """Lấy các sự kiện chưa gửi."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM event_queue WHERE sent = 0 ORDER BY id ASC LIMIT ?", (limit,)
            ).fetchall()
            return [
                {
                    "id": r["id"],
                    "idempotency_key": r["idempotency_key"],
                    "event_type": r["event_type"],
                    "subject": r["subject"],
                    "duration_sec": r["duration_sec"],
                    "policy_version": r["policy_version"],
                    "created_at": r["created_at"],
                }
                for r in rows
            ]

    def mark_events_sent(self, event_ids: list[int]):
        """Đánh dấu các sự kiện đã gửi thành công lên server."""
        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        with self._get_connection() as conn:
            conn.execute(f"UPDATE event_queue SET sent = 1 WHERE id IN ({placeholders})", event_ids)
            # Dọn dẹp các event đã gửi quá 7 ngày
            conn.execute("DELETE FROM event_queue WHERE sent = 1 AND id IN (" + placeholders + ")")
            conn.commit()

    def get_screen_time_today(self) -> int:
        """Lấy số giây đã sử dụng hôm nay (tự reset nếu sang ngày mới)."""
        today_str = date.today().isoformat()
        with self._get_connection() as conn:
            row = conn.execute("SELECT current_date, quota_used_seconds FROM agent_state WHERE id = 1").fetchone()
            if row and row["current_date"] != today_str:
                # Sang ngày mới -> reset quota_used_seconds về 0
                conn.execute(
                    "UPDATE agent_state SET current_date = ?, quota_used_seconds = 0, is_locked = 0 WHERE id = 1",
                    (today_str,),
                )
                conn.commit()
                return 0
            return row["quota_used_seconds"] if row else 0

    def add_screen_time(self, seconds: int) -> int:
        """Cộng dồn thời gian dùng máy trong ngày."""
        today_str = date.today().isoformat()
        with self._get_connection() as conn:
            row = conn.execute("SELECT current_date, quota_used_seconds FROM agent_state WHERE id = 1").fetchone()
            if row and row["current_date"] != today_str:
                new_used = seconds
                conn.execute(
                    "UPDATE agent_state SET current_date = ?, quota_used_seconds = ?, is_locked = 0 WHERE id = 1",
                    (today_str, new_used),
                )
            else:
                new_used = (row["quota_used_seconds"] if row else 0) + seconds
                conn.execute("UPDATE agent_state SET quota_used_seconds = ? WHERE id = 1", (new_used,))
            conn.commit()
            return new_used

    def set_lock_status(self, is_locked: bool):
        with self._get_connection() as conn:
            conn.execute("UPDATE agent_state SET is_locked = ? WHERE id = 1", (1 if is_locked else 0,))
            conn.commit()

    def get_lock_status(self) -> bool:
        with self._get_connection() as conn:
            row = conn.execute("SELECT is_locked FROM agent_state WHERE id = 1").fetchone()
            return bool(row["is_locked"]) if row else False

    def update_server_contact(self):
        """Cập nhật timestamp lần cuối liên lạc được với Server."""
        with self._get_connection() as conn:
            conn.execute("UPDATE agent_state SET last_server_contact_ts = ? WHERE id = 1", (time.time(),))
            conn.commit()

    def check_connection_grace_period(self) -> str:
        """Kiểm tra chính sách mất kết nối 2 giai đoạn theo mục 5.5 Design.md:

        - Giai đoạn 1 (0-3 ngày): 'normal' (áp dụng bình thường cached policy).
        - Giai đoạn 2 (>3 ngày tới 14 ngày): 'degraded' (an toàn suy giảm).
        - Sau 14 ngày: 'degraded' (vẫn giữ an toàn, không fail-open).
        """
        with self._get_connection() as conn:
            row = conn.execute("SELECT last_server_contact_ts FROM agent_state WHERE id = 1").fetchone()
            if not row or row["last_server_contact_ts"] == 0:
                return "normal"
            elapsed_days = (time.time() - row["last_server_contact_ts"]) / 86400.0
            if elapsed_days > 3.0:
                return "degraded"
            return "normal"
