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

try:
    import psutil
except ImportError:
    psutil = None

from storage import AgentStorage


class PolicyEnforcer:
    def __init__(self, storage: AgentStorage):
        self.storage = storage
        self.running = False
        self.manual_locked = False
        self._lock = threading.Lock()
        self._last_tick_time = time.time()
        self._screen_time_buffer = 0
        self._last_lock_time = 0.0

    @staticmethod
    def is_workstation_locked() -> bool:
        """Kiểm tra màn hình Windows có đang bị khóa hay không."""
        if sys.platform != "win32":
            return False
        try:
            desk = ctypes.windll.user32.OpenInputDesktop(0, False, 0x0100)  # DESKTOP_SWITCHDESKTOP
            if desk:
                ctypes.windll.user32.CloseDesktop(desk)
                return False  # Màn hình đang mở, người dùng đang ở Desktop
            return True  # Màn hình đang ở chế độ Lock Screen / Winlogon
        except Exception:
            return False

    def lock_workstation(self, manual: bool = False, reason: str = ""):
        """Khóa màn hình máy tính Windows."""
        if manual:
            self.manual_locked = True
        self.storage.set_lock_status(True)
        self._last_lock_time = time.time()

        prefix = f" [{reason}]" if reason else ""
        if sys.platform == "win32":
            try:
                print(f"[Enforcer] 🔒 ĐANG THỰC HIỆN KHÓA MÁY (LockWorkStation)...{prefix}")
                ctypes.windll.user32.LockWorkStation()
            except Exception as e:
                print(f"[Enforcer] Lỗi gọi LockWorkStation: {e}")
        else:
            print(f"[Enforcer] 🔒 Giả lập khóa màn hình (không phải Windows){prefix}")

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

    def check_schedule(self, schedule: dict, now_dt: datetime | None = None) -> bool:
        """Kiểm tra thời gian hiện tại có nằm trong khung giờ cho phép hay không.

        Hỗ trợ:
        1. Ma trận lịch tuần 7x48 (độ phân giải 30 phút, Thứ Hai = 0 .. Chủ Nhật = 6, 48 ô/ngày).
        2. Khung giờ start_time - end_time (fallback tương thích ngược).
        """
        if not schedule:
            return True

        if now_dt is None:
            now_dt = datetime.now()

        # 1. Kiểm tra ma trận lịch tuần 7x48 (độ phân giải 30 phút)
        matrix = schedule.get("matrix")
        if matrix and isinstance(matrix, list) and len(matrix) == 7:
            day = now_dt.weekday()  # 0 = Thứ Hai, ..., 6 = Chủ Nhật
            slot = now_dt.hour * 2 + (now_dt.minute // 30)  # 0 đến 47 (30 phút / ô)
            if 0 <= day < 7 and 0 <= slot < 48:
                day_slots = matrix[day]
                if isinstance(day_slots, list) and len(day_slots) == 48:
                    return bool(day_slots[slot])

        # 2. Fallback tương thích ngược: start_time / end_time
        start_str = schedule.get("start_time")
        end_str = schedule.get("end_time")
        if not start_str or not end_str:
            return True
        try:
            now_time = now_dt.strftime("%H:%M")
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
        if isinstance(app_rules, list):
            raw_blacklist = app_rules
        elif isinstance(app_rules, dict):
            raw_blacklist = app_rules.get("blacklist", [])
        else:
            raw_blacklist = []

        if not raw_blacklist or psutil is None:
            return

        cleaned_blacklist = set()
        for b in raw_blacklist:
            if not b:
                continue
            b_str = str(b).strip().lower()
            b_name = Path(b_str).name
            cleaned_blacklist.add(b_name)
            cleaned_blacklist.add(b_name.removesuffix(".exe"))

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pname = (proc.info["name"] or "").lower()
                pname_no_exe = pname.removesuffix(".exe")
                if pname in cleaned_blacklist or pname_no_exe in cleaned_blacklist:
                    print(f"[Enforcer] 🚫 PHÁT HIỆN ỨNG DỤNG BỊ CẤM: {pname} (PID: {proc.info['pid']}) -> TIẾN HÀNH ĐÓNG!")
                    try:
                        proc.kill()
                    except Exception:
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
                    if self.manual_locked:
                        lock_reason = "Khóa theo lệnh phụ huynh"
                    elif quota_exceeded:
                        lock_reason = f"Đã hết hạn mức ngày ({used_seconds}/{daily_limit_sec}s)"
                    else:
                        day_names = ["Thứ Hai", "Thứ Ba", "Thứ Tư", "Thứ Năm", "Thứ Sáu", "Thứ Bảy", "Chủ Nhật"]
                        now_dt = datetime.now()
                        lock_reason = f"Ngoài khung giờ cho phép ({day_names[now_dt.weekday()]} lúc {now_dt.strftime('%H:%M')} - Lịch tuần 7x48) -> Khóa máy trong 5s"

                    # Kiểm tra hành động khóa:
                    # - Nếu chưa ở trạng thái khóa: khóa ngay lập tức!
                    # - Nếu đã từng khóa nhưng màn hình đang mở (trẻ đăng nhập lại),
                    #   hoặc đã quá 5 giây kể từ lần khóa trước: khóa lại ngay (đảm bảo trong 5s)!
                    needs_lock_action = False
                    if not is_already_locked:
                        needs_lock_action = True
                    else:
                        time_since_last_lock = now - self._last_lock_time
                        workstation_unlocked = not self.is_workstation_locked()
                        if workstation_unlocked or time_since_last_lock >= 5.0:
                            needs_lock_action = True

                    if needs_lock_action:
                        self.lock_workstation(reason=lock_reason)
                else:
                    # Đang trong hạn mức và trong khung giờ hợp lệ -> Nếu trước đó từng bị khóa thì mở lại
                    if self.storage.get_lock_status():
                        print("[Enforcer] 🔓 Đủ điều kiện sử dụng máy -> Giải phóng trạng thái khóa.")
                        self.storage.set_lock_status(False)

                    # 3. Đếm thời gian sử dụng màn hình (khi máy không bị khóa)
                    # Nếu màn hình đang khóa (Lock Screen), không đếm thời gian
                    workstation_locked = self.is_workstation_locked()
                    if not workstation_locked and elapsed > 0:
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
                            self.lock_workstation(reason="Hết hạn mức ngày")

            except Exception as e:
                print(f"[Enforcer] Lỗi trong vòng lặp enforcer: {e}")

            time.sleep(poll_interval)

    def stop(self):
        self.running = False
