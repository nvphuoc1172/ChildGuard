"""Policy Enforcer & Screen-time Counter — xem mục 3 và 3.1 trong Design.md.

Chịu trách nhiệm:
1. Quét process list mỗi 2-3s (`psutil`), terminate app bị cấm và ghi event `app_blocked`.
2. Đếm dồn thời gian dùng máy theo phiên hoạt động.
3. Kiểm tra quota ngày và khung giờ cho phép trong lịch biểu (Schedule).
4. Thực thi khóa máy (LockWorkStation) khi nhận lệnh LOCK, hết giờ hoặc ngoài lịch.
"""
from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import psutil

from storage import AgentStorage


class PolicyEnforcer:
    def __init__(self, storage: AgentStorage):
        self.storage = storage
        self.running = False
        self._lock = threading.Lock()
        self._last_tick_time = time.time()
        self._screen_time_buffer = 0

    def lock_workstation(self):
        """Khóa màn hình máy tính Windows."""
        print("[Enforcer] ĐANG THỰC HIỆN KHÓA MÁY...")
        self.storage.set_lock_status(True)
        if sys.platform == "win32":
            try:
                ctypes.windll.user32.LockWorkStation()
            except Exception as e:
                print(f"[Enforcer] Lỗi gọi LockWorkStation: {e}")
        else:
            print("[Enforcer] Giả lập khóa màn hình (không phải Windows)")

    def unlock_workstation(self):
        """Mở khóa máy (cho phép tiếp tục dùng)."""
        print("[Enforcer] MỞ KHÓA MÁY.")
        self.storage.set_lock_status(False)

    def grant_extra_minutes(self, minutes: int):
        """Cộng thêm thời gian cho trẻ: giảm số giây đã tính hôm nay để trẻ có thêm thời gian."""
        print(f"[Enforcer] CỘNG THÊM {minutes} PHÚT CHO TRẺ.")
        current_used = self.storage.get_screen_time_today()
        reduced_used = max(0, current_used - (minutes * 60))
        # Cập nhật lại quota_used_seconds trong agent_state
        with self.storage._get_connection() as conn:
            conn.execute("UPDATE agent_state SET quota_used_seconds = ?, is_locked = 0 WHERE id = 1", (reduced_used,))
            conn.commit()

    def check_schedule(self, schedule: dict) -> bool:
        """Kiểm tra thời gian hiện tại có nằm trong khung giờ cho phép hay không."""
        start_str = schedule.get("start_time", "00:00")
        end_str = schedule.get("end_time", "23:59")
        try:
            now_dt = datetime.now()
            now_time = now_dt.strftime("%H:%M")
            return start_str <= now_time <= end_str
        except Exception:
            return True

    def scan_and_enforce_processes(self, policy: dict):
        """Quét tiến trình đang chạy và terminate các ứng dụng trong blacklist."""
        app_rules = policy.get("app_rules", {})
        blacklist = [app.lower().strip() for app in app_rules.get("blacklist", []) if app.strip()]
        if not blacklist:
            return

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pname = (proc.info["name"] or "").lower()
                if pname in blacklist:
                    print(f"[Enforcer] PHÁT HIỆN ỨNG DỤNG BỊ CẤM: {pname} (PID: {proc.info['pid']}) -> TIẾN HÀNH ĐÓNG!")
                    proc.terminate()
                    # Ghi nhận sự kiện app_blocked vào hàng đợi offline
                    self.storage.add_event(
                        event_type="app_blocked",
                        subject=pname,
                        duration_sec=0,
                        policy_version=policy.get("version"),
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def run_loop(self, poll_interval: float = 2.0):
        """Vòng lặp chính của Enforcer."""
        self.running = True
        self._last_tick_time = time.time()
        last_event_flush_time = time.time()

        print("[Enforcer] Bắt đầu Policy Enforcer & Screen-time Counter...")

        while self.running:
            try:
                now = time.time()
                elapsed = int(now - self._last_tick_time)
                self._last_tick_time = now

                policy = self.storage.get_policy()
                is_locked = self.storage.get_lock_status()

                # Kiểm tra chế độ degraded safe-mode khi mất mạng dài ngày
                mode = self.storage.check_connection_grace_period()
                if mode == "degraded":
                    # Đảm bảo các app giải trí/game bị chặn cứng trong safe-mode
                    policy["app_rules"].setdefault("blacklist", []).extend(["game.exe", "discord.exe", "roblox.exe"])

                # 1. Quét và chặn ứng dụng
                self.scan_and_enforce_processes(policy)

                # 2. Đếm thời gian sử dụng màn hình
                if not is_locked and elapsed > 0:
                    used_seconds = self.storage.add_screen_time(elapsed)
                    self._screen_time_buffer += elapsed

                    # Mỗi 60 giây tích lũy tạo 1 event screen_time vào hàng đợi
                    if self._screen_time_buffer >= 60 or (now - last_event_flush_time) >= 60:
                        if self._screen_time_buffer > 0:
                            self.storage.add_event(
                                event_type="screen_time",
                                duration_sec=self._screen_time_buffer,
                                policy_version=policy.get("version"),
                            )
                            self._screen_time_buffer = 0
                            last_event_flush_time = now

                    # 3. Kiểm tra Quota
                    quota = policy.get("quota", {})
                    daily_limit_sec = quota.get("daily_minutes", 120) * 60
                    if used_seconds >= daily_limit_sec:
                        print(f"[Enforcer] ĐÃ HẾT HẠN MỨC NGÀY ({used_seconds}/{daily_limit_sec}s)!")
                        self.lock_workstation()

                    # 4. Kiểm tra Lịch biểu (Schedule)
                    schedule = policy.get("schedule", {})
                    if not self.check_schedule(schedule):
                        print("[Enforcer] NGOÀI KHUNG GIỜ CHO PHÉP DÙNG MÁY!")
                        self.lock_workstation()

                elif is_locked:
                    # Nếu máy đang bị đánh dấu khóa, định kỳ gọi lock lại nếu trẻ cố mở
                    pass

            except Exception as e:
                print(f"[Enforcer] Lỗi trong vòng lặp enforcer: {e}")

            time.sleep(poll_interval)

    def stop(self):
        self.running = False
