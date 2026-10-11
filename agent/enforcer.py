"""Policy Enforcer & Screen-time Counter — xem mục 3 và 3.1 trong Design.md.

Chịu trách nhiệm:
1. Quét process list mỗi 2-3s (`psutil`), terminate app bị cấm và ghi event `app_blocked`.
2. Đếm dồn thời gian dùng máy theo thời gian thực (chỉ khi người dùng đăng nhập hoạt động, không tính lúc màn hình khóa).
3. Kiểm tra quota ngày và khung giờ cho phép trong lịch biểu (Schedule).
4. Tự động chuyển đổi trạng thái Khóa / Mở khóa linh hoạt:
   - Khi tăng hạn mức hoặc trong khung giờ hợp lệ -> Tự động giải phóng trạng thái khóa.
   - Khi hết quota ngày, ngoài khung giờ hoặc có lệnh từ phụ huynh -> Khóa màn hình (LockWorkStation).
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
        self.manual_locked = False
        self._lock = threading.Lock()
        self._last_tick_time = time.time()
        self._screen_time_buffer = 0

    def is_windows_locked(self) -> bool:
        """Kiểm tra màn hình Windows có đang ở trạng thái khóa (Lock screen / Winlogon) hay không."""
        if sys.platform != "win32":
            return False
        try:
            user32 = ctypes.windll.user32
            # OpenInputDesktop trả về 0 nếu workstation đang bị khóa hoặc ở secure desktop
            h_desk = user32.OpenInputDesktop(0, False, 0x0100)  # 0x0100 = DESKTOP_SWITCHDESKTOP
            if not h_desk:
                return True
            user32.CloseDesktop(h_desk)
            return False
        except Exception:
            return False

    def lock_workstation(self, manual: bool = False):
        """Khóa màn hình máy tính Windows."""
        if manual:
            self.manual_locked = True
        self.storage.set_lock_status(True)

        if sys.platform == "win32":
            try:
                if not self.is_windows_locked():
                    print("[Enforcer] 🔒 ĐANG THỰC HIỆN KHÓA MÁY (LockWorkStation)...")
                    ctypes.windll.user32.LockWorkStation()
            except Exception as e:
                print(f"[Enforcer] Lỗi gọi LockWorkStation: {e}")
        else:
            print("[Enforcer] 🔒 Giả lập khóa màn hình (không phải Windows)")

    def unlock_workstation(self):
        """Mở khóa máy (cho phép tiếp tục dùng)."""
        print("[Enforcer] 🔓 MỞ KHÓA MÁY THEO LỆNH.")
        self.manual_locked = False
        self.storage.set_lock_status(False)

    def grant_extra_minutes(self, minutes: int):
        """Cộng thêm thời gian cho trẻ: giảm số giây đã tính hôm nay để trẻ có thêm thời gian."""
        print(f"[Enforcer] ⏱️ CỘNG THÊM {minutes} PHÚT CHO TRẺ.")
        self.manual_locked = False
        current_used = self.storage.get_screen_time_today()
        reduced_used = max(0, current_used - (minutes * 60))
        with self.storage._get_connection() as conn:
            conn.execute("UPDATE agent_state SET quota_used_seconds = ?, is_locked = 0 WHERE id = 1", (reduced_used,))
            conn.commit()

    def check_schedule(self, schedule: dict) -> bool:
        """Kiểm tra thời gian hiện tại có nằm trong khung giờ cho phép hay không."""
        if not schedule:
            return True
        start_str = schedule.get("start_time")
        end_str = schedule.get("end_time")
        if not start_str or not end_str:
            return True
        try:
            now_time = datetime.now().strftime("%H:%M")
            if start_str <= end_str:
                return start_str <= now_time <= end_str
            else:
                # Khung giờ qua đêm (ví dụ: 20:00 -> 06:00 sáng hôm sau)
                return now_time >= start_str or now_time <= end_str
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
                # Kiểm tra cả tên đầy đủ hoặc tên không có .exe
                matched = any(pname == b or pname.removesuffix(".exe") == b.removesuffix(".exe") for b in blacklist)
                if matched:
                    print(f"[Enforcer] 🚫 PHÁT HIỆN ỨNG DỤNG BỊ CẤM: {pname} (PID: {proc.info['pid']}) -> TIẾN HÀNH ĐÓNG!")
                    proc.terminate()
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
                quota = policy.get("quota", {})
                daily_limit_sec = int(quota.get("daily_minutes", 120)) * 60
                schedule = policy.get("schedule", {})

                # Chế độ degraded safe-mode khi mất mạng dài ngày
                mode = self.storage.check_connection_grace_period()
                if mode == "degraded":
                    policy["app_rules"].setdefault("blacklist", []).extend(["game.exe", "discord.exe", "roblox.exe"])

                # 1. Quét và chặn ứng dụng
                self.scan_and_enforce_processes(policy)

                # 2. Kiểm tra điều kiện khóa máy
                used_seconds = self.storage.get_screen_time_today()
                in_schedule = self.check_schedule(schedule)
                quota_exceeded = used_seconds >= daily_limit_sec

                should_lock = self.manual_locked or quota_exceeded or (not in_schedule)

                if should_lock:
                    is_already_locked = self.storage.get_lock_status()
                    if not is_already_locked:
                        if self.manual_locked:
                            print("[Enforcer] 🔒 KHÓA MÁY THEO LỆNH PHỤ HUYNH!")
                        elif quota_exceeded:
                            print(f"[Enforcer] 🔒 ĐÃ HẾT HẠN MỨC NGÀY ({used_seconds}/{daily_limit_sec}s) -> KHÓA MÁY!")
                        elif not in_schedule:
                            s_start = schedule.get("start_time", "07:00")
                            s_end = schedule.get("end_time", "21:30")
                            print(f"[Enforcer] 🔒 NGOÀI KHUNG GIỜ CHO PHÉP DÙNG MÁY ({s_start} - {s_end}) -> KHÓA MÁY!")
                        self.lock_workstation()
                else:
                    # Đang trong hạn mức và trong khung giờ hợp lệ -> Nếu trước đó từng bị khóa thì mở lại
                    if self.storage.get_lock_status():
                        print("[Enforcer] 🔓 Đủ điều kiện sử dụng máy -> Giải phóng trạng thái khóa.")
                        self.storage.set_lock_status(False)

                    # 3. Đếm thời gian sử dụng màn hình (chỉ đếm khi máy không bị khóa màn hình)
                    session_locked = self.is_windows_locked()
                    if not session_locked and elapsed > 0:
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

                        # Kiểm tra lại ngay sau khi cộng: nếu vừa chạm mốc hạn mức thì khóa ngay
                        if used_seconds >= daily_limit_sec:
                            print(f"[Enforcer] 🔒 VỪA HẾT HẠN MỨC NGÀY ({used_seconds}/{daily_limit_sec}s) -> KHÓA MÁY!")
                            self.lock_workstation()

            except Exception as e:
                print(f"[Enforcer] Lỗi trong vòng lặp enforcer: {e}")

            time.sleep(poll_interval)

    def stop(self):
        self.running = False
