"""Policy Enforcer & Screen-time Counter — xem mục 3 và 3.1 trong Design.md.

Chịu trách nhiệm:
1. Quét process list mỗi 2-3s, ghi app_start/app_stop và terminate app bị cấm với blocked_app.
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
import re
import shutil
import sys
import threading
import time
from datetime import datetime, timedelta
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

# Các tiến trình hệ thống thiết yếu tuyệt đối không bao giờ bị terminate.
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


def _read_file_hash_windows(p_str: str, block_size: int = 65536) -> str | None:
    """Đọc hash tệp trên Windows dùng Win32 CreateFileW với cờ chia sẻ đầy đủ (FILE_SHARE_READ|WRITE|DELETE).
    
    Hữu ích khi tệp thực thi đang chạy bị Windows OS hoặc trình bảo vệ khóa chia sẻ đọc thông thường.
    """
    if sys.platform != "win32":
        return None
    try:
        import msvcrt
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        FILE_SHARE_DELETE = 0x00000004
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x00000080
        FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000

        handle = ctypes.windll.kernel32.CreateFileW(
            p_str,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            None,
        )
        if handle == -1 or handle == 0xFFFFFFFF:
            return None
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            with os.fdopen(fd, "rb", closefd=True) as f:
                h = hashlib.sha256()
                while chunk := f.read(block_size):
                    h.update(chunk)
                return h.hexdigest().lower()
        except Exception:
            ctypes.windll.kernel32.CloseHandle(handle)
            return None
    except Exception:
        return None


def get_file_sha256(file_path: str | Path, block_size: int = 65536) -> str | None:
    """Tính mã SHA-256 của tệp thực thi với bộ đệm bộ nhớ theo (mtime, size)."""
    try:
        clean_path = str(file_path).strip().strip('"').strip("'")
        if not clean_path:
            return None
        p = Path(clean_path)
        if not p.is_file():
            return None
        stat = p.stat()
        mtime = stat.st_mtime
        size = stat.st_size
        p_str = os.path.abspath(clean_path)

        cached = _FILE_HASH_CACHE.get(p_str)
        if cached and cached[0] == mtime and cached[1] == size:
            return cached[2]

        digest = None
        try:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                while chunk := f.read(block_size):
                    h.update(chunk)
            digest = h.hexdigest().lower()
        except (PermissionError, OSError):
            # Trên Windows: tệp đang chạy có thể bị khóa quyền đọc chuẩn -> Thử qua CreateFileW với FILE_SHARE_*
            if sys.platform == "win32":
                digest = _read_file_hash_windows(p_str, block_size=block_size)

        if digest:
            _FILE_HASH_CACHE[p_str] = (mtime, size, digest)
        return digest
    except Exception:
        return None


def _extract_base_filename(p: str) -> str:
    """Trích xuất tên file thực thi hỗ trợ cả đường dẫn Windows (\\) và Unix (/)."""
    return p.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()


def parse_app_rule_entry(entry: str | dict) -> dict:
    """Chuẩn hóa mục quy tắc ứng dụng hỗ trợ tối đa các định dạng:
      - Tên tiến trình: "game.exe", "C:\\Games\\game.exe"
      - Tên tiến trình kèm hash: "game.exe:a3c5...", "game.exe:sha256:a3c5...", "game.exe a3c5..."
      - Chỉ nhập SHA-256: "a3c5...64hex...", "sha256:a3c5...", "sha-256:a3c5..."
      - Đầu ra Certutil có khoảng trắng: "a3 c5 14 ... 64hex..."
      - Dạng dict: {"name": "game.exe", "sha256": "a3c5..."}
    Trả về dict: {"name": str | None, "sha256": str | None}
    """
    if isinstance(entry, dict):
        name = entry.get("name") or entry.get("app") or entry.get("process")
        h = entry.get("sha256") or entry.get("hash")
        name_clean = _extract_base_filename(str(name)) if name else None
        h_clean = str(h).strip().lower() if h else None
        if h_clean:
            h_clean = re.sub(r"[^0-9a-fA-F]", "", h_clean).lower()
        return {"name": name_clean, "sha256": h_clean or None}

    entry_str = str(entry).strip()
    if not entry_str:
        return {"name": None, "sha256": None}

    entry_str = entry_str.strip('"\'`')

    # Gom các cặp hex 2 ký tự cách nhau bởi khoảng trắng/dấu gạch ngang (chuẩn certutil Windows)
    collapsed = re.sub(r"(?<=[0-9a-fA-F]{2})[\s\-]+(?=[0-9a-fA-F]{2})", "", entry_str)

    # Tìm mã hash hex: ưu tiên 64 ký tự hex (chuẩn SHA-256) hoặc từ 32-64 ký tự hex
    hex_match = re.search(r"\b([0-9a-fA-F]{64})\b", collapsed)
    if not hex_match:
        hex_match = re.search(r"[:=\s]([0-9a-fA-F]{32,64})\b", collapsed)
        if not hex_match:
            hex_match = re.search(r"\b([0-9a-fA-F]{32,64})\b", collapsed)

    found_hash = None
    remaining_text = collapsed
    if hex_match:
        found_hash = hex_match.group(1).lower()
        remaining_text = (collapsed[:hex_match.start()] + " " + collapsed[hex_match.end():]).strip()

    if remaining_text:
        # Loại bỏ các tiền tố / hậu tố nhãn như sha256, sha-256, sha, hash, certutil
        remaining_text = re.sub(r"\b(sha-?256|sha|hash|certutil)\b", "", remaining_text, flags=re.IGNORECASE)
        # Bỏ các ký tự phân cách dư thừa
        remaining_text = re.sub(r"^[\s:=,\-\[\]\(\)]+|[\s:=,\-\[\]\(\)]+$", "", remaining_text).strip()

    found_name = None
    if remaining_text:
        found_name = _extract_base_filename(remaining_text)
        if not found_name or found_name in ("none", "null", ""):
            found_name = None

    return {"name": found_name, "sha256": found_hash}


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
    """Kiểm tra một tiến trình theo danh sách đen ứng dụng.

    Quy tắc đối chiếu danh tính (Identity Resolution):
    - Dựa vào mã băm SHA-256 của tệp thực thi để nhận diện đúng bản chất ứng dụng.
    - Ví dụ: Trẻ đổi tên notepad.exe thành game.exe:
      Do SHA-256 trùng khớp với mã băm của notepad.exe trong known_system_hashes,
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
        raw_list = app_rules
    elif isinstance(app_rules, dict):
        # Chỉ danh sách chặn có hiệu lực. Các trường cũ khác bị bỏ qua để
        # không vô tình biến ứng dụng được phép thành ứng dụng bị chặn.
        raw_list = app_rules.get("blacklist", [])

    # Đăng ký các hash đã biết từ app_rules vào bảng danh tính
    all_rule_entries = []
    if isinstance(app_rules, dict):
        all_rule_entries.extend(app_rules.get("blacklist", []))
    else:
        all_rule_entries.extend(raw_list)

    for entry in all_rule_entries:
        r = parse_app_rule_entry(entry)
        if r.get("sha256") and r.get("name"):
            hash_to_identity[r["sha256"]] = r["name"]
        elif r.get("sha256") and not r.get("name"):
            if r["sha256"] not in hash_to_identity:
                hash_to_identity[r["sha256"]] = f"SHA256-{r['sha256'][:8]}"

    parsed_rules = [parse_app_rule_entry(entry) for entry in raw_list]

    # 3. Xác định danh tính thực sự (Identified App) của tiến trình theo mã băm SHA-256
    identified_app = pname
    if h_proc and h_proc in hash_to_identity:
        identified_app = hash_to_identity[h_proc]

    # 4. Chế độ duy nhất: chặn các ứng dụng trong blacklist.
    for r in parsed_rules:
        r_name = r.get("name")
        r_hash = r.get("sha256")

        # TH 1: Rule chỉ định mã hash
        if r_hash:
            if h_proc and h_proc == r_hash:
                lbl = f" {r_name}" if r_name else ""
                return True, f"Khớp mã SHA-256 bị cấm{lbl} ({r_hash[:12]}...)", identified_app

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


def show_windows_popup(title: str, message: str, level: str = "warning"):
    """Hiển thị thông báo trên màn hình Windows (chạy trong luồng riêng không block)."""
    if sys.platform != "win32":
        print(f"[Windows Notification] 📢 [{title}] {message}")
        return
    try:
        # 0x00000010 = MB_ICONERROR/STOP cho chặn app/web; 0x00000030 = MB_ICONWARNING
        icon_flag = 0x00000010 if level in ("app_blocked", "dns_blocked") else (
            0x00000030 if level in ("warning", "urgent", "grace_period") else 0x00000040
        )
        flags = icon_flag | 0x00040000 | 0x00010000 | 0x00200000
        threading.Thread(
            target=lambda: ctypes.windll.user32.MessageBoxW(0, message, title, flags),
            daemon=True,
        ).start()
    except Exception as e:
        print(f"[Windows Notification] Lỗi hiển thị MessageBox: {e}")


class PolicyEnforcer:
    def __init__(
        self,
        storage: AgentStorage,
        known_system_hashes: dict[str, str] | None = None,
        lock_checker=None,
        safe_lock_once: bool = False,
        idle_getter=None,
        notifier=None,
    ):
        self.storage = storage
        self.known_system_hashes = (
            known_system_hashes if known_system_hashes is not None else get_system_known_app_hashes()
        )
        self._lock_checker = lock_checker or self.is_workstation_locked
        self.safe_lock_once = safe_lock_once
        self._idle_getter = idle_getter or get_idle_seconds
        self._notifier = notifier or self._default_notifier
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
        self._last_process_scan_mono = 0.0
        self._observed_processes: dict[int, tuple[str, float]] = {}
        self._process_baseline_ready = False

        # Bộ đệm thời gian thông báo chặn app & web để chống spam
        self._last_app_block_notif: dict[str, float] = {}
        self._last_dns_block_notif: dict[str, float] = {}

        # Trạng thái cảnh báo trước 10, 5, 1 phút và ân hạn 60 giây
        self._warned_milestones: set[int] = set()
        self._in_grace_period: bool = False
        self._grace_period_start: float | None = None
        self.grace_seconds_left: int = 0
        self.active_notification: dict | None = None
        self.notification_history: list[dict] = []
        self.effective_remaining_seconds: int = 0
        self.effective_restriction_type: str = "none"

    def _default_notifier(self, notif: dict):
        """Bộ phát thông báo mặc định: in log console và kích hoạt popup trên Windows."""
        print(f"[Enforcer Notifier] 📢 [{notif.get('title')}] {notif.get('message')}")
        show_windows_popup(
            title=notif.get("title", "ChildGuard"),
            message=notif.get("message", ""),
            level=notif.get("level", "warning"),
        )

    def _emit_warning(
        self,
        milestone: int,
        remaining_seconds: int,
        restriction_type: str,
        title: str,
        message: str,
        level: str = "warning",
    ) -> dict:
        """Tạo và phát thông báo cảnh báo/ân hạn."""
        notif = {
            "id": f"notif_{int(time.time() * 1000)}",
            "milestone": milestone,
            "remaining_seconds": remaining_seconds,
            "restriction_type": restriction_type,
            "title": title,
            "message": message,
            "level": level,
            "in_grace_period": self._in_grace_period,
            "grace_seconds_left": self.grace_seconds_left,
            "created_at": datetime.now().isoformat(),
        }
        self.active_notification = notif
        self.notification_history.append(notif)
        if len(self.notification_history) > 50:
            self.notification_history = self.notification_history[-50:]

        try:
            self.storage.add_event(type="quota_warning", subject=None, duration_sec=remaining_seconds)
        except Exception:
            pass

        if self._notifier:
            try:
                self._notifier(notif)
            except Exception as e:
                print(f"[Enforcer] Lỗi trong notifier callback: {e}")

        return notif

    def _emit_event_notification(
        self,
        title: str,
        message: str,
        level: str = "warning",
        event_type: str = "",
        subject: str = "",
    ) -> dict:
        """Tạo và phát thông báo sự kiện (chặn app / chặn web) ra ngoài Windows."""
        notif = {
            "id": f"notif_{int(time.time() * 1000)}_{event_type}",
            "milestone": -1,
            "remaining_seconds": self.effective_remaining_seconds,
            "restriction_type": event_type,
            "title": title,
            "message": message,
            "level": level,
            "in_grace_period": self._in_grace_period,
            "grace_seconds_left": self.grace_seconds_left,
            "created_at": datetime.now().isoformat(),
        }
        self.active_notification = notif
        self.notification_history.append(notif)
        if len(self.notification_history) > 50:
            self.notification_history = self.notification_history[-50:]

        if self._notifier:
            try:
                self._notifier(notif)
            except Exception as e:
                print(f"[Enforcer] Lỗi trong notifier callback: {e}")

        return notif

    def notify_app_blocked(self, app_name: str, reason: str = ""):
        """Phát thông báo ra ngoài màn hình Windows khi ứng dụng bị chặn."""
        now = time.time()
        last_time = self._last_app_block_notif.get(app_name, 0.0)
        if now - last_time < 8.0:
            return
        self._last_app_block_notif[app_name] = now

        msg = f"Ứng dụng '{app_name}' đã bị đóng vì nằm trong danh sách hạn chế theo quy định của cha mẹ."
        if reason and "sha-256" in reason.lower():
            msg = f"Ứng dụng '{app_name}' đã bị đóng vì nhận diện tệp thực thi bị cấm (khớp mã băm SHA-256)."

        self._emit_event_notification(
            title="🚫 ChildGuard — Ứng dụng bị hạn chế",
            message=msg,
            level="app_blocked",
            event_type="blocked_app",
            subject=app_name,
        )

    def notify_dns_blocked(self, domain: str):
        """Phát thông báo ra ngoài màn hình Windows khi tên miền web bị chặn."""
        now = time.time()
        last_time = self._last_dns_block_notif.get(domain, 0.0)
        if now - last_time < 8.0:
            return
        self._last_dns_block_notif[domain] = now

        msg = f"Trang web '{domain}' đã bị chặn truy cập để bảo vệ an toàn cho em theo quy định của gia đình."
        self._emit_event_notification(
            title="🌐 ChildGuard — Trang web bị hạn chế",
            message=msg,
            level="dns_blocked",
            event_type="blocked_domain",
            subject=domain,
        )

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
        was_locked = self.storage.get_lock_status()
        if manual:
            self.manual_locked = True
        self.storage.set_lock_status(True)
        if not was_locked:
            self.storage.add_event(type="locked", subject=None)
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

    def unlock_workstation(self, emit_event: bool = True):
        """Mở khóa máy (cho phép tiếp tục dùng)."""
        print("[Enforcer] 🔓 MỞ KHÓA MÁY THEO LỆNH.")
        self.manual_locked = False
        self._in_grace_period = False
        self._grace_period_start = None
        self.grace_seconds_left = 0
        self._warned_milestones.clear()
        self.active_notification = None
        self.storage.set_lock_status(False)
        if emit_event:
            self.storage.add_event(type="override_granted", subject=None)

    def grant_extra_minutes(self, minutes: int):
        """Cộng thêm thời gian cho trẻ: giảm số giây đã tính hôm nay để trẻ có thêm thời gian."""
        print(f"[Enforcer] ⏱️ CỘNG THÊM {minutes} PHÚT CHO TRẺ.")
        self.manual_locked = False
        self._in_grace_period = False
        self._grace_period_start = None
        self.grace_seconds_left = 0
        self._warned_milestones.clear()
        self.active_notification = None
        current_used = self.storage.get_screen_time_today()
        reduced_used = max(0, current_used - (minutes * 60))
        with self.storage._get_connection() as conn:
            conn.execute("UPDATE agent_state SET quota_used_seconds = ?, is_locked = 0 WHERE id = 1", (reduced_used,))
            conn.commit()
        self.storage.add_event(type="override_granted", subject=None, duration_sec=max(0, minutes * 60))

    def reset_usage_cache(self):
        """Xóa toàn bộ dữ liệu bộ đệm trên agent khi phụ huynh yêu cầu xóa dữ liệu."""
        print("[Enforcer] 🧹 RESET TOÀN BỘ DỮ LIỆU SỬ DỤNG VÀ HÀNG ĐỢI SỰ KIỆN THEO LỆNH XÓA DỮ LIỆU.")
        self.manual_locked = False
        self._in_grace_period = False
        self._grace_period_start = None
        self.grace_seconds_left = 0
        self._warned_milestones.clear()
        self.active_notification = None
        self._subsecond_buffer = 0.0
        self.storage.clear_all_cached_data()
        self.unlock_workstation(emit_event=False)

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

    def get_schedule_remaining_seconds(self, schedule: dict, now_dt: datetime | None = None) -> int | None:
        """Tính số giây còn lại trong khung giờ cho phép của lịch biểu hiện tại.

        Trả về:
          - int >= 0: Số giây còn lại trước khi kết thúc khung giờ cho phép.
          - None: Không cấu hình lịch biểu (cho phép không giới hạn theo lịch).
        """
        if not schedule:
            return None

        if now_dt is None or not isinstance(now_dt, datetime):
            now_dt = self._get_effective_local_datetime()

        matrix = schedule.get("matrix")
        # 1. Ma trận lịch tuần 7x48
        if matrix and isinstance(matrix, list) and len(matrix) == 7:
            day = now_dt.weekday()
            slot = now_dt.hour * 2 + (now_dt.minute // 30)
            if not (0 <= day < 7 and 0 <= slot < 48):
                return 0

            day_slots = matrix[day]
            if not (isinstance(day_slots, list) and len(day_slots) == 48):
                return None

            # Nếu slot hiện tại đang bị khóa -> còn 0 giây
            if not bool(day_slots[slot]):
                return 0

            # Tính số giây còn lại trong slot 30 phút hiện tại
            minute_in_slot = now_dt.minute % 30
            sec_left_curr_slot = (30 - minute_in_slot) * 60 - now_dt.second
            total_sec = max(0, sec_left_curr_slot)

            # Quét các slot tiếp theo liên tục còn được phép (== 1)
            curr_day = day
            curr_slot = slot + 1
            for _ in range(48 * 7):
                if curr_slot >= 48:
                    curr_slot = 0
                    curr_day = (curr_day + 1) % 7

                next_day_slots = matrix[curr_day]
                if isinstance(next_day_slots, list) and len(next_day_slots) == 48 and bool(next_day_slots[curr_slot]):
                    total_sec += 30 * 60
                    curr_slot += 1
                else:
                    break

            return total_sec

        # 2. Khung giờ start_time - end_time (fallback)
        start_str = schedule.get("start_time")
        end_str = schedule.get("end_time")
        if not start_str or not end_str:
            return None

        try:
            now_time = now_dt.strftime("%H:%M")
            if not self.check_schedule(schedule, now_dt):
                return 0

            end_parts = end_str.split(":")
            end_hour, end_minute = int(end_parts[0]), int(end_parts[1])
            end_dt = now_dt.replace(hour=end_hour, minute=end_minute, second=0, microsecond=0)

            if start_str <= end_str:
                diff = (end_dt - now_dt).total_seconds()
                return max(0, int(diff))
            else:
                if now_time >= start_str:
                    end_dt += timedelta(days=1)
                diff = (end_dt - now_dt).total_seconds()
                return max(0, int(diff))
        except Exception:
            return None

    def get_quota_remaining_seconds(self, policy: dict) -> int | None:
        """Tính số giây còn lại theo hạn mức ngày (Quota)."""
        quota = policy.get("quota", {})
        daily_minutes = quota.get("daily_minutes")
        if daily_minutes is None:
            return None
        daily_limit_sec = int(daily_minutes) * 60
        used_seconds = self.storage.get_screen_time_today()
        return max(0, daily_limit_sec - used_seconds)

    def get_effective_remaining_seconds(self, policy: dict, now_dt: datetime | None = None) -> tuple[int, str]:
        """Tính số giây còn lại thực tế và lý do tương ứng (hạn mức ngày hoặc lịch biểu).

        Trả về: (remaining_seconds, restriction_type)
        restriction_type: "quota" | "schedule" | "none"
        """
        if now_dt is None or not isinstance(now_dt, datetime):
            now_dt = self._get_effective_local_datetime()

        quota_rem = self.get_quota_remaining_seconds(policy)
        sched_rem = self.get_schedule_remaining_seconds(policy.get("schedule", {}), now_dt)

        if quota_rem is not None and sched_rem is not None:
            if sched_rem < quota_rem:
                return sched_rem, "schedule"
            else:
                return quota_rem, "quota"
        elif quota_rem is not None:
            return quota_rem, "quota"
        elif sched_rem is not None:
            return sched_rem, "schedule"
        else:
            return 86400, "none"

    def check_and_emit_warnings(self, policy: dict, now_dt: datetime | None = None):
        """Kiểm tra và phát cảnh báo trước 10, 5, 1 phút."""
        rem_sec, res_type = self.get_effective_remaining_seconds(policy, now_dt)

        if res_type == "none":
            return

        reason_str = "Hạn mức ngày" if res_type == "quota" else "Lịch tuần"

        # Nếu thời gian còn lại tăng lên (ví dụ: phụ huynh cấp thêm giờ hoặc đổi lịch)
        if rem_sec > 600:
            self._warned_milestones.clear()
            self._in_grace_period = False
            self._grace_period_start = None
        elif rem_sec > 300:
            self._warned_milestones.discard(5)
            self._warned_milestones.discard(1)
            self._in_grace_period = False
            self._grace_period_start = None
        elif rem_sec > 60:
            self._warned_milestones.discard(1)
            self._in_grace_period = False
            self._grace_period_start = None

        # Kiểm tra các mốc cảnh báo 10, 5, 1 phút
        if 0 < rem_sec <= 60:
            if 1 not in self._warned_milestones:
                self._warned_milestones.update({10, 5, 1})
                self._emit_warning(
                    milestone=1,
                    remaining_seconds=rem_sec,
                    restriction_type=res_type,
                    title="⚠️ ChildGuard — SẮP HẾT GIỜ (Còn 1 phút)",
                    message=f"Chỉ còn 1 phút nữa máy tính sẽ bị khóa ({reason_str})! Hãy lưu bài ngay bây giờ!",
                    level="urgent",
                )
        elif 60 < rem_sec <= 300:
            if 5 not in self._warned_milestones:
                self._warned_milestones.update({10, 5})
                mins_text = max(1, round(rem_sec / 60))
                self._emit_warning(
                    milestone=5,
                    remaining_seconds=rem_sec,
                    restriction_type=res_type,
                    title="ChildGuard — Cảnh báo sắp hết giờ (Còn 5 phút)",
                    message=f"Bạn còn {mins_text} phút sử dụng máy tính ({reason_str})! Vui lòng lưu các bài làm và tài liệu dở dang.",
                    level="warning",
                )
        elif 300 < rem_sec <= 600:
            if 10 not in self._warned_milestones:
                self._warned_milestones.add(10)
                mins_text = max(1, round(rem_sec / 60))
                self._emit_warning(
                    milestone=10,
                    remaining_seconds=rem_sec,
                    restriction_type=res_type,
                    title="ChildGuard — Cảnh báo thời gian (Còn 10 phút)",
                    message=f"Bạn còn {mins_text} phút sử dụng máy tính ({reason_str}). Hãy chuẩn bị hoàn thành công việc!",
                    level="info",
                )

    def scan_and_enforce_processes(self, policy: dict):
        """Quét tiến trình và thực thi blacklist ứng dụng kèm đối chiếu SHA-256."""
        if psutil is None:
            return

        app_rules = policy.get("app_rules", {})
        rule_entries = []
        if isinstance(app_rules, dict):
            rule_entries = app_rules.get("blacklist", []) or []
        elif isinstance(app_rules, list):
            rule_entries = app_rules
        has_app_restrictions = bool(rule_entries)

        observed_now: dict[int, tuple[str, float]] = {}
        now_mono = time.monotonic()

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pinfo = proc.info
                pname = (pinfo.get("name") or "").strip()
                if not pname:
                    continue
                pid = int(pinfo.get("pid") or 0)
                normalized_name = os.path.basename(pname).casefold()
                previous = self._observed_processes.get(pid)
                if previous is None or previous[0] != normalized_name:
                    if previous is not None:
                        self.storage.add_event(
                            type="app_stop",
                            subject=previous[0],
                            duration_sec=max(0, int(now_mono - previous[1])),
                            policy_version=policy.get("version"),
                        )
                    if self._process_baseline_ready:
                        self.storage.add_event(
                            type="app_start",
                            subject=normalized_name,
                            policy_version=policy.get("version"),
                        )
                    observed_now[pid] = (normalized_name, now_mono)
                else:
                    observed_now[pid] = previous

                pexe = pinfo.get("exe")
                if not pexe:
                    try:
                        pexe = proc.exe()
                    except Exception:
                        pexe = None
                if not pexe:
                    try:
                        cmd = proc.cmdline()
                        if cmd and cmd[0]:
                            cand = cmd[0].strip().strip('"').strip("'")
                            if os.path.isfile(cand):
                                pexe = cand
                    except Exception:
                        pass
                if not pexe:
                    try:
                        pexe = shutil.which(pname)
                    except Exception:
                        pass

                proc_sha256 = None
                if has_app_restrictions and pexe:
                    proc_sha256 = get_file_sha256(pexe)

                if has_app_restrictions:
                    is_blocked, reason, identified_app = check_process_rule(
                        proc_name=pname,
                        proc_sha256=proc_sha256,
                        app_rules=app_rules,
                        known_system_hashes=self.known_system_hashes,
                    )
                else:
                    is_blocked, reason, identified_app = False, "", normalized_name

                if is_blocked:
                    display_name = f"{pname} (nhận diện: {identified_app})" if identified_app != pname.lower() else pname
                    print(f"[Enforcer] 🚫 PHÁT HIỆN ỨNG DỤNG BỊ CHẶN: {display_name} (PID: {pinfo.get('pid')}) - Lý do: {reason} -> TIẾN HÀNH ĐÓNG!")
                    try:
                        proc.kill()
                    except Exception:
                        proc.terminate()
                    self.storage.add_event(
                        type="blocked_app",
                        subject=normalized_name,
                        duration_sec=0,
                        policy_version=policy.get("version"),
                    )
                    # Thông báo ra ngoài màn hình Windows cho bé
                    self.notify_app_blocked(display_name, reason=reason)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        for pid, (app_name, started_mono) in self._observed_processes.items():
            if pid not in observed_now:
                self.storage.add_event(
                    type="app_stop",
                    subject=app_name,
                    duration_sec=max(0, int(now_mono - started_mono)),
                    policy_version=policy.get("version"),
                )
        self._observed_processes = observed_now
        self._process_baseline_ready = True

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

        # 1. Quét và chặn ứng dụng. Throttle theo monotonic thực để các lời gọi
        # tick dồn dập không quét/hash toàn bộ process list nhiều lần vô ích.
        scan_mono = time.monotonic()
        if scan_mono - self._last_process_scan_mono >= 1.5:
            self.scan_and_enforce_processes(policy)
            self._last_process_scan_mono = scan_mono

        # 2. Kiểm tra trạng thái máy: Khóa màn hình & Không hoạt động (Idle > 5 phút)
        workstation_locked = bool(self._lock_checker())
        self.is_locked_screen = workstation_locked

        idle_sec = float(self._idle_getter())
        self.current_idle_seconds = idle_sec
        self.is_idle = (idle_sec >= 300.0)

        # 3. Đánh giá cảnh báo trước 10, 5, 1 phút
        rem_sec, res_type = self.get_effective_remaining_seconds(policy)
        self.effective_remaining_seconds = rem_sec
        self.effective_restriction_type = res_type
        self.check_and_emit_warnings(policy)

        # 4. Kiểm tra điều kiện khóa máy & Khoảng ân hạn 60 giây để trẻ lưu bài
        used_seconds = self.storage.get_screen_time_today()
        in_schedule = self.check_schedule(schedule)
        quota_exceeded = used_seconds >= daily_limit_sec
        time_expired = quota_exceeded or (not in_schedule) or (rem_sec <= 0 and res_type != "none")

        should_lock = False
        lock_reason = ""
        is_already_locked = self.storage.get_lock_status()

        if self.manual_locked:
            should_lock = True
            lock_reason = "Khóa theo lệnh phụ huynh"
            self._in_grace_period = False
            self._grace_period_start = None
            self.grace_seconds_left = 0
        elif time_expired:
            if is_already_locked and workstation_locked:
                # Máy đã khóa từ trước trên Lock Screen -> giữ nguyên trạng thái khóa
                should_lock = True
                if quota_exceeded:
                    lock_reason = f"Đã hết hạn mức ngày ({used_seconds}/{daily_limit_sec}s)"
                else:
                    day_names = ["Thứ Hai", "Thứ Ba", "Thứ Tư", "Thứ Năm", "Thứ Sáu", "Thứ Bảy", "Chủ Nhật"]
                    now_dt = self._get_effective_local_datetime()
                    lock_reason = f"Ngoài khung giờ cho phép ({day_names[now_dt.weekday()]} lúc {now_dt.strftime('%H:%M')} - Lịch tuần 7x48) -> Khóa máy trong 5s"
            else:
                # Trẻ đang sử dụng trên Desktop và vừa chạm mốc hết giờ:
                # KÍCH HOẠT KHOẢNG ÂN HẠN 60 GIÂY ĐỂ LƯU BÀI!
                if not self._in_grace_period:
                    self._in_grace_period = True
                    self._grace_period_start = now
                    self.grace_seconds_left = 60
                    res_type_name = "Hạn mức ngày" if quota_exceeded else "Khung giờ cho phép"
                    self._emit_warning(
                        milestone=0,
                        remaining_seconds=0,
                        restriction_type=res_type,
                        title="⚠️ ChildGuard — ÂN HẠN 60 GIÂY ĐỂ LƯU BÀI",
                        message=f"{res_type_name} đã hết! Bạn có 60 giây ân hạn để lưu bài và tài liệu. Máy sẽ khóa sau 60 giây.",
                        level="grace_period",
                    )
                    should_lock = False  # CHƯA KHÓA MÁY để trẻ lưu bài
                else:
                    elapsed_grace = now - (self._grace_period_start or now)
                    if elapsed_grace < 60.0:
                        self.grace_seconds_left = max(0, int(60.0 - elapsed_grace))
                        should_lock = False  # Tiếp tục cho trẻ lưu bài trong 60 giây
                    else:
                        # Đã hết 60 giây ân hạn -> Khóa máy!
                        self._in_grace_period = False
                        self.grace_seconds_left = 0
                        should_lock = True
                        res_type_name = "Hạn mức ngày" if quota_exceeded else "Khung giờ quy định"
                        lock_reason = f"Hết thời gian ân hạn 60 giây để lưu bài ({res_type_name})"
        else:
            # Chưa hết giờ và đang trong khung giờ hợp lệ:
            self._in_grace_period = False
            self._grace_period_start = None
            self.grace_seconds_left = 0

        if should_lock:
            needs_lock_action = False
            if not is_already_locked:
                needs_lock_action = True
            else:
                time_since_last_lock = now - self._last_lock_time
                workstation_unlocked = not workstation_locked
                if not self.safe_lock_once and (workstation_unlocked or time_since_last_lock >= 5.0):
                    needs_lock_action = True

            if needs_lock_action:
                self.lock_workstation(reason=lock_reason)
        else:
            # Đang trong hạn mức hoặc đang trong ân hạn -> Nếu trước đó từng bị đánh dấu khóa thì giải phóng
            if not self._in_grace_period and self.storage.get_lock_status():
                print("[Enforcer] 🔓 Đủ điều kiện sử dụng máy -> Giải phóng trạng thái khóa.")
                self.storage.set_lock_status(False)

            # 5. Đếm thời gian sử dụng thực (Screen-time Counter):
            # - Không tính khi máy khóa (workstation_locked == True)
            # - Không tính khi không có thao tác quá 5 phút (self.is_idle == True)
            # - Sử dụng bộ tích lũy sub-second float để triệt tiêu sai số làm tròn (sai số <= +-1s/giờ << +-30s)
            if not workstation_locked and not self.is_idle and elapsed_float > 0:
                self._subsecond_buffer += elapsed_float
                whole_sec = int(self._subsecond_buffer)
                if whole_sec > 0:
                    self._subsecond_buffer -= whole_sec
                    used_seconds = self.storage.add_screen_time(whole_sec)

    def run_loop(self, poll_interval: float = 2.0):
        """Vòng lặp chính của Enforcer."""
        self.running = True
        self._last_tick_mono = time.monotonic()

        print("[Enforcer] Bắt đầu Policy Enforcer & Screen-time Counter...")

        while self.running:
            try:
                now_mono = time.monotonic()
                elapsed_float = max(0.0, now_mono - self._last_tick_mono)
                self._last_tick_mono = now_mono

                self.tick(elapsed_float)

            except Exception as e:
                print(f"[Enforcer] Lỗi trong vòng lặp enforcer: {e}")

            time.sleep(poll_interval)

    def stop(self):
        self.running = False

