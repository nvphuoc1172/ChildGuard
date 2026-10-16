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
import hashlib
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

try:
    from storage import AgentStorage
except ImportError:
    try:
        from app.agent.storage import AgentStorage
    except ImportError:
        AgentStorage = None

# Bộ đệm hash tệp thực thi theo (đường dẫn, mtime, size) để tránh đọc lại đĩa mỗi 2 giây
_FILE_HASH_CACHE: dict[str, tuple[float, int, str]] = {}

# Các tiến trình hệ thống thiết yếu tuyệt đối không bao giờ được terminate (kể cả trong chế độ Whitelist)
ESSENTIAL_SYSTEM_PROCESSES = {
    # Windows core & system processes
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe",
    "dwm.exe", "explorer.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe",
    "conhost.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "python.exe",
    "pythonw.exe", "wscript.exe", "cscript.exe", "dllhost.exe", "runtimebroker.exe",
    "searchhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "textinputhost.exe", "taskmgr.exe", "spoolsv.exe", "childguard.exe",
    "agent.exe", "devenv.exe", "code.exe",
    # Unix / Linux essential processes
    "init", "systemd", "bash", "sh", "zsh", "pytest", "sshd", "kthreadd",
}


def get_file_sha256(file_path: str | Path, block_size: int = 65536) -> str | None:
    """Tính mã SHA-256 của tệp thực thi với bộ đệm bộ nhớ theo (mtime, size)."""
    try:
        p = Path(file_path)
        if not p.is_file():
            return None
        stat = p.stat()
        mtime = stat.st_mtime
        size = stat.st_size
        p_str = str(p.resolve())

        cached = _FILE_HASH_CACHE.get(p_str)
        if cached and cached[0] == mtime and cached[1] == size:
            return cached[2]

        h = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(block_size):
                h.update(chunk)
        digest = h.hexdigest().lower()
        _FILE_HASH_CACHE[p_str] = (mtime, size, digest)
        return digest
    except Exception:
        return None


def _extract_base_filename(p: str) -> str:
    """Trích xuất tên file thực thi hỗ trợ cả đường dẫn Windows (\\) và Unix (/)."""
    return p.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()


def parse_app_rule_entry(entry: str | dict) -> dict:
    """Chuẩn hóa mục quy tắc ứng dụng.

    Hỗ trợ:
      - "game.exe"
      - "game.exe:a3c5...64hex..."
      - "C:\\Path\\game.exe:a3c5..."
      - "game.exe a3c5..."
      - "a3c5...64hex..." (chỉ có sha256)
      - {"name": "game.exe", "sha256": "a3c5..."}
    Trả về dict: {"name": str | None, "sha256": str | None}
    """
    if isinstance(entry, dict):
        name = entry.get("name") or entry.get("app") or entry.get("process")
        h = entry.get("sha256") or entry.get("hash")
        name_clean = _extract_base_filename(str(name)) if name else None
        h_clean = str(h).strip().lower() if h else None
        return {"name": name_clean, "sha256": h_clean}

    entry_str = str(entry).strip()
    if not entry_str:
        return {"name": None, "sha256": None}

    # Format name:hash (dùng rsplit để không bị nhầm ký tự ổ đĩa Windows C:\...)
    if ":" in entry_str:
        p0, p1 = entry_str.rsplit(":", 1)
        p0, p1 = p0.strip(), p1.strip()
        if len(p1) >= 32 and all(c in "0123456789abcdefABCDEF" for c in p1):
            return {"name": _extract_base_filename(p0), "sha256": p1.lower()}
        if len(p0) >= 32 and all(c in "0123456789abcdefABCDEF" for c in p0):
            return {"name": _extract_base_filename(p1), "sha256": p0.lower()}

    # Format name hash (cách nhau bởi khoảng trắng)
    parts = entry_str.split()
    if len(parts) == 2:
        p0, p1 = parts[0].lower(), parts[1].lower()
        if len(p1) >= 32 and all(c in "0123456789abcdefABCDEF" for c in p1):
            return {"name": _extract_base_filename(p0), "sha256": p1}
        elif len(p0) >= 32 and all(c in "0123456789abcdefABCDEF" for c in p0):
            return {"name": _extract_base_filename(p1), "sha256": p0}

    # Nếu chỉ có mã SHA-256 (64 ký tự hex)
    if len(entry_str) == 64 and all(c in "0123456789abcdefABCDEF" for c in entry_str):
        return {"name": None, "sha256": entry_str.lower()}

    # Chỉ có tên file/đường dẫn
    return {"name": _extract_base_filename(entry_str), "sha256": None}


def get_system_known_app_hashes() -> dict[str, str]:
    """Tìm mã SHA-256 của các ứng dụng hệ thống chuẩn (như notepad.exe, calc.exe) trên Windows."""
    known: dict[str, str] = {}
    if sys.platform == "win32":
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        candidates = [
            ("notepad.exe", Path(sys_root) / "System32" / "notepad.exe"),
            ("notepad.exe", Path(sys_root) / "notepad.exe"),
            ("calc.exe", Path(sys_root) / "System32" / "calc.exe"),
            ("mspaint.exe", Path(sys_root) / "System32" / "mspaint.exe"),
            ("write.exe", Path(sys_root) / "System32" / "write.exe"),
        ]
        for name, path in candidates:
            if name not in known and path.is_file():
                h = get_file_sha256(path)
                if h:
                    known[name.lower()] = h
    return known


def check_process_rule(
    proc_name: str,
    proc_sha256: str | None,
    app_rules: dict | list,
    known_system_hashes: dict[str, str] | None = None,
) -> tuple[bool, str, str]:
    """Kiểm tra một tiến trình xem có bị chặn hay được phép theo chính sách.

    Quy tắc đối chiếu danh tính (Identity Resolution):
    - Dựa vào mã băm SHA-256 của tệp thực thi để nhận diện đúng bản chất ứng dụng.
    - Ví dụ: Trẻ đổi tên notepad.exe thành game.exe:
      Do SHA-256 trùng khớp với mã băm của notepad.exe (trong known_system_hashes hoặc whitelist),
      hệ thống nhận diện đúng ứng dụng là notepad.exe, KHÔNG chặn nhầm dù tên tiến trình là game.exe.
    - Ngược lại: Trẻ đổi tên game.exe thành notepad.exe:
      Mã băm SHA-256 không trùng khớp với notepad.exe chuẩn (hoặc trùng với mã băm game bị cấm),
      hệ thống nhận diện là game giả mạo và tiến hành CHẶN ngay lập tức.

    Trả về: (is_blocked: bool, reason: str, identified_app: str)
    """
    pname = (proc_name or "").lower().strip()
    pname_no_exe = pname.removesuffix(".exe")
    h_proc = (proc_sha256 or "").lower().strip() or None

    # 1. Các tiến trình hệ thống thiết yếu luôn an toàn, không bao giờ bị đóng
    if pname in ESSENTIAL_SYSTEM_PROCESSES or pname_no_exe in ESSENTIAL_SYSTEM_PROCESSES:
        return False, "Tiến trình hệ thống thiết yếu", pname

    # 2. Xây dựng bản đồ nhận diện danh tính (Hash -> Tên ứng dụng chuẩn)
    hash_to_identity: dict[str, str] = {}
    if known_system_hashes:
        for k_name, k_hash in known_system_hashes.items():
            if k_hash:
                hash_to_identity[k_hash.lower()] = k_name.lower()

    raw_list = []
    if isinstance(app_rules, list):
        mode = "blacklist"
        raw_list = app_rules
    elif isinstance(app_rules, dict):
        mode = app_rules.get("mode", "blacklist").lower()
        if mode == "whitelist":
            raw_list = app_rules.get("whitelist", [])
        else:
            raw_list = app_rules.get("blacklist", [])
    else:
        mode = "blacklist"

    # Đăng ký các hash đã biết từ app_rules vào bảng danh tính
    all_rule_entries = []
    if isinstance(app_rules, dict):
        all_rule_entries.extend(app_rules.get("blacklist", []))
        all_rule_entries.extend(app_rules.get("whitelist", []))
    else:
        all_rule_entries.extend(raw_list)

    for entry in all_rule_entries:
        r = parse_app_rule_entry(entry)
        if r.get("sha256") and r.get("name"):
            hash_to_identity[r["sha256"]] = r["name"]

    parsed_rules = [parse_app_rule_entry(entry) for entry in raw_list]

    # 3. Xác định danh tính thực sự (Identified App) của tiến trình theo mã băm SHA-256
    identified_app = pname
    if h_proc and h_proc in hash_to_identity:
        identified_app = hash_to_identity[h_proc]

    # 4. Kiểm tra theo chế độ (Whitelist vs Blacklist)
    if mode == "whitelist":
        if not parsed_rules:
            # Danh sách cho phép trống -> Mặc định không cấm (tránh khóa toàn bộ hệ thống khi chưa cài đặt)
            return False, "Danh sách cho phép trống", identified_app

        is_whitelisted = False
        match_reason = ""

        for r in parsed_rules:
            r_name = r.get("name")
            r_hash = r.get("sha256")

            # Nếu rule có cả sha256 và name
            if r_name and r_hash:
                if h_proc and h_proc == r_hash:
                    is_whitelisted = True
                    match_reason = f"Khớp mã SHA-256 ứng dụng cho phép {r_name}"
                    break
            # Nếu rule chỉ có sha256
            elif r_hash and not r_name:
                if h_proc and h_proc == r_hash:
                    is_whitelisted = True
                    match_reason = "Khớp mã SHA-256 được cấp phép"
                    break
            # Nếu rule chỉ có tên ứng dụng
            elif r_name and not r_hash:
                r_name_no_exe = r_name.removesuffix(".exe")
                # Khớp theo danh tính thực tế (identified_app) hoặc tên tiến trình
                if identified_app == r_name or identified_app.removesuffix(".exe") == r_name_no_exe:
                    # Kiểm tra xem có bị giả mạo tên không:
                    expected_hash = known_system_hashes.get(r_name) if known_system_hashes else None
                    if expected_hash and h_proc and h_proc != expected_hash:
                        continue  # Giả mạo tên ứng dụng cho phép nhưng hash khác
                    is_whitelisted = True
                    match_reason = f"Thuộc danh sách cho phép ({r_name})"
                    break
                elif pname == r_name or pname_no_exe == r_name_no_exe:
                    expected_hash = known_system_hashes.get(r_name) if known_system_hashes else None
                    if expected_hash and h_proc and h_proc != expected_hash:
                        continue
                    is_whitelisted = True
                    match_reason = f"Thuộc danh sách cho phép ({r_name})"
                    break

        if not is_whitelisted:
            return True, f"Ứng dụng {pname} (nhận diện: {identified_app}) không nằm trong danh sách cho phép (Whitelist)", identified_app
        return False, match_reason, identified_app

    else:
        # CHẾ ĐỘ BLACKLIST: Chặn các ứng dụng trong blacklist
        for r in parsed_rules:
            r_name = r.get("name")
            r_hash = r.get("sha256")

            # TH 1: Rule chỉ định mã hash
            if r_hash:
                if h_proc and h_proc == r_hash:
                    return True, f"Khớp mã SHA-256 bị cấm {r_name or ''} ({r_hash[:12]}...)", identified_app

            # TH 2: Rule chỉ định tên ứng dụng
            if r_name:
                r_name_no_exe = r_name.removesuffix(".exe")
                # ĐẶC BIỆT XỬ LÝ ĐỔI TÊN:
                # Nếu tiến trình bị đổi tên từ notepad.exe thành game.exe (pname là game.exe),
                # nhưng danh tính thực sự identified_app là notepad.exe (do hash trùng notepad.exe):
                # -> KHÔNG CHẶN vì đây thực chất là notepad.exe!
                if pname == r_name or pname_no_exe == r_name_no_exe:
                    if identified_app != pname and identified_app != r_name and (identified_app.removesuffix(".exe") != r_name_no_exe):
                        continue
                    if r_hash and h_proc and h_proc != r_hash:
                        continue
                    return True, f"Nằm trong danh sách cấm ({r_name})", identified_app

                # Nếu tên tiến trình không khớp (ví dụ: game.exe đổi tên thành notepad.exe),
                # nhưng danh tính thực tế identified_app là r_name (do hash trùng game.exe bị cấm):
                if identified_app == r_name or identified_app.removesuffix(".exe") == r_name_no_exe:
                    return True, f"Phát hiện ứng dụng bị cấm {r_name} giả mạo dưới tên {pname}", identified_app

        return False, "Ứng dụng hợp lệ", identified_app


class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint),
        ("dwTime", ctypes.c_uint),
    ]


def get_idle_seconds() -> float:
    """Trả về số giây kể từ lần tương tác bàn phím/chuột cuối cùng (Win32 API)."""
    if sys.platform != "win32":
        return 0.0
    try:
        lii = LASTINPUTINFO()
        lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
            millis = (ctypes.windll.kernel32.GetTickCount() - lii.dwTime) & 0xFFFFFFFF
            return max(0.0, millis / 1000.0)
    except Exception:
        pass
    return 0.0


class PolicyEnforcer:
    def __init__(
        self,
        storage: AgentStorage,
        known_system_hashes: dict[str, str] | None = None,
        lock_checker=None,
        idle_getter=None,
    ):
        self.storage = storage
        self.known_system_hashes = (
            known_system_hashes if known_system_hashes is not None else get_system_known_app_hashes()
        )
        self._lock_checker = lock_checker or self.is_workstation_locked
        self._idle_getter = idle_getter or get_idle_seconds
        self.running = False
        self.manual_locked = False
        self.is_idle = False
        self.current_idle_seconds = 0.0
        self.is_locked_screen = False
        self._lock = threading.Lock()
        self._last_tick_mono = time.monotonic()
        self._subsecond_buffer = 0.0
        self._screen_time_buffer = 0
        self._last_lock_time = 0.0

    @staticmethod
    def is_workstation_locked() -> bool:
        """Kiểm tra màn hình Windows có đang bị khóa hay không."""
        if sys.platform != "win32":
            return False
        try:
            # 1. Thử OpenInputDesktop: nếu mở được và hợp lệ -> màn hình đang mở (Desktop bình thường)
            desk = ctypes.windll.user32.OpenInputDesktop(0, False, 0x0100)  # DESKTOP_SWITCHDESKTOP
            if desk:
                ctypes.windll.user32.CloseDesktop(desk)
                return False

            # 2. Nếu OpenInputDesktop trả về 0 (xảy ra khi chạy trong Service hoặc phiên không có quyền trực tiếp),
            # kiểm tra GetForegroundWindow: nếu có handle cửa sổ foreground đang hiển thị -> người dùng đang tương tác
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            if hwnd != 0:
                return False

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

    def _get_effective_local_datetime(self) -> datetime:
        """Lấy datetime giờ địa phương thực tế (ưu tiên timestamp đồng bộ máy chủ, an toàn với mock/fallback)."""
        try:
            if hasattr(self.storage, "get_synced_local_datetime"):
                dt = self.storage.get_synced_local_datetime()
                if isinstance(dt, datetime):
                    return dt
        except Exception:
            pass

        try:
            if hasattr(self.storage, "get_server_utc_timestamp"):
                ts = self.storage.get_server_utc_timestamp()
                if isinstance(ts, (int, float)):
                    return datetime.fromtimestamp(ts)
        except Exception:
            pass

        return datetime.now()

    def check_schedule(self, schedule: dict, now_dt: datetime | None = None) -> bool:
        """Kiểm tra thời gian hiện tại có nằm trong khung giờ cho phép hay không.

        Hỗ trợ:
        1. Ma trận lịch tuần 7x48 (độ phân giải 30 phút, Thứ Hai = 0 .. Chủ Nhật = 6, 48 ô/ngày).
        2. Khung giờ start_time - end_time (fallback tương thích ngược).
        """
        if not schedule:
            return True

        if now_dt is None or not isinstance(now_dt, datetime):
            now_dt = self._get_effective_local_datetime()

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
        """Quét tiến trình đang chạy và thực thi chính sách cho phép / chặn ứng dụng kèm đối chiếu SHA-256."""
        if psutil is None:
            return

        app_rules = policy.get("app_rules", {})

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pinfo = proc.info
                pname = (pinfo.get("name") or "").strip()
                if not pname:
                    continue

                pexe = pinfo.get("exe")
                proc_sha256 = None
                if pexe:
                    proc_sha256 = get_file_sha256(pexe)

                is_blocked, reason, identified_app = check_process_rule(
                    proc_name=pname,
                    proc_sha256=proc_sha256,
                    app_rules=app_rules,
                    known_system_hashes=self.known_system_hashes,
                )

                if is_blocked:
                    display_name = f"{pname} (nhận diện: {identified_app})" if identified_app != pname.lower() else pname
                    print(f"[Enforcer] 🚫 PHÁT HIỆN ỨNG DỤNG BỊ CHẶN: {display_name} (PID: {pinfo.get('pid')}) - Lý do: {reason} -> TIẾN HÀNH ĐÓNG!")
                    try:
                        proc.kill()
                    except Exception:
                        proc.terminate()
                    self.storage.add_event(
                        event_type="app_blocked",
                        subject=display_name,
                        duration_sec=0,
                        policy_version=policy.get("version"),
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def tick(self, elapsed_float: float):
        """Thực thi một chu kỳ kiểm tra chính sách và đếm thời gian sử dụng thực."""
        now = time.time()
        policy = self.storage.get_policy()
        quota = policy.get("quota", {})
        daily_limit_sec = int(quota.get("daily_minutes", 120)) * 60
        schedule = policy.get("schedule", {})

        # Chế độ degraded safe-mode khi mất mạng dài ngày
        mode = self.storage.check_connection_grace_period()
        if mode == "degraded":
            ar = policy.setdefault("app_rules", {})
            if isinstance(ar, dict):
                ar.setdefault("blacklist", []).extend(["game.exe", "discord.exe", "roblox.exe"])
            elif isinstance(ar, list):
                ar.extend(["game.exe", "discord.exe", "roblox.exe"])

        # 1. Quét và chặn ứng dụng
        self.scan_and_enforce_processes(policy)

        # 2. Kiểm tra trạng thái máy: Khóa màn hình & Không hoạt động (Idle > 5 phút)
        workstation_locked = bool(self._lock_checker())
        self.is_locked_screen = workstation_locked

        idle_sec = float(self._idle_getter())
        self.current_idle_seconds = idle_sec
        self.is_idle = (idle_sec >= 300.0)

        # 3. Kiểm tra điều kiện khóa máy
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
                now_dt = self._get_effective_local_datetime()
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
                workstation_unlocked = not workstation_locked
                if workstation_unlocked or time_since_last_lock >= 5.0:
                    needs_lock_action = True

            if needs_lock_action:
                self.lock_workstation(reason=lock_reason)
        else:
            # Đang trong hạn mức và trong khung giờ hợp lệ -> Nếu trước đó từng bị khóa thì mở lại
            if self.storage.get_lock_status():
                print("[Enforcer] 🔓 Đủ điều kiện sử dụng máy -> Giải phóng trạng thái khóa.")
                self.storage.set_lock_status(False)

            # 4. Đếm thời gian sử dụng thực (Screen-time Counter):
            # - Không tính khi máy khóa (workstation_locked == True)
            # - Không tính khi không có thao tác quá 5 phút (self.is_idle == True)
            # - Sử dụng bộ tích lũy sub-second float để triệt tiêu sai số làm tròn (sai số <= +-1s/giờ << +-30s)
            if not workstation_locked and not self.is_idle and elapsed_float > 0:
                self._subsecond_buffer += elapsed_float
                whole_sec = int(self._subsecond_buffer)
                if whole_sec > 0:
                    self._subsecond_buffer -= whole_sec
                    used_seconds = self.storage.add_screen_time(whole_sec)
                    self._screen_time_buffer += whole_sec

                    # Mỗi 60 giây tích lũy tạo 1 event screen_time vào hàng đợi
                    if self._screen_time_buffer >= 60:
                        self.storage.add_event(
                            event_type="screen_time",
                            duration_sec=self._screen_time_buffer,
                            policy_version=policy.get("version"),
                        )
                        self._screen_time_buffer = 0

                    # Kiểm tra lại ngay sau khi cộng: nếu vừa chạm mốc hạn mức thì khóa ngay
                    if used_seconds >= daily_limit_sec:
                        print(f"[Enforcer] 🔒 VỪA HẾT HẠN MỨC NGÀY ({used_seconds}/{daily_limit_sec}s) -> KHÓA MÁY!")
                        self.lock_workstation(reason="Hết hạn mức ngày")

    def run_loop(self, poll_interval: float = 2.0):
        """Vòng lặp chính của Enforcer."""
        self.running = True
        self._last_tick_mono = time.monotonic()
        last_flush_mono = time.monotonic()

        print("[Enforcer] Bắt đầu Policy Enforcer & Screen-time Counter...")

        while self.running:
            try:
                now_mono = time.monotonic()
                elapsed_float = max(0.0, now_mono - self._last_tick_mono)
                self._last_tick_mono = now_mono

                self.tick(elapsed_float)

                if self._screen_time_buffer > 0 and (now_mono - last_flush_mono) >= 60.0:
                    policy = self.storage.get_policy()
                    self.storage.add_event(
                        event_type="screen_time",
                        duration_sec=self._screen_time_buffer,
                        policy_version=policy.get("version"),
                    )
                    self._screen_time_buffer = 0
                    last_flush_mono = now_mono

            except Exception as e:
                print(f"[Enforcer] Lỗi trong vòng lặp enforcer: {e}")

            time.sleep(poll_interval)

    def stop(self):
        self.running = False

