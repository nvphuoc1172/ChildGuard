"""Console logging helpers for the interactive Windows Agent process."""
from __future__ import annotations

import builtins
import ctypes
import sys
import threading
from datetime import datetime


_ORIGINAL_PRINT = builtins.print
_PRINT_LOCK = threading.Lock()
_CONFIGURED = False


def _timestamped_print(*args, **kwargs):
    kwargs.setdefault("flush", True)
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S%z")
    with _PRINT_LOCK:
        _ORIGINAL_PRINT(f"[{stamp}]", *args, **kwargs)


def configure_agent_console() -> None:
    """Add timestamps, disable buffering and prevent Quick Edit pauses."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True, write_through=True)
        except (AttributeError, ValueError):
            pass
    builtins.print = _timestamped_print

    if sys.platform == "win32":
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleTitleW("ChildGuard Agent")
            std_input_handle = -10
            enable_extended_flags = 0x0080
            enable_quick_edit_mode = 0x0040
            handle = kernel32.GetStdHandle(std_input_handle)
            mode = ctypes.c_uint()
            if handle and kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                safe_mode = (mode.value | enable_extended_flags) & ~enable_quick_edit_mode
                kernel32.SetConsoleMode(handle, safe_mode)
        except Exception:
            pass

