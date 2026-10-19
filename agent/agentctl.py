"""Password-gated management command used by the ChildGuard installer."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

CONFIG = Path(os.environ.get("PROGRAMDATA", str(Path.home()))) / "ChildGuard" / "admin.json"


def _derive(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000).hex()


def set_password() -> None:
    first = getpass.getpass("Tạo mật khẩu quản trị ChildGuard: ")
    second = getpass.getpass("Nhập lại mật khẩu: ")
    if len(first) < 12 or first != second:
        raise SystemExit("Mật khẩu phải trùng nhau và có ít nhất 12 ký tự.")
    salt = secrets.token_bytes(16)
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps({"salt": salt.hex(), "hash": _derive(first, salt)}), encoding="utf-8")
    if sys.platform == "win32":
        subprocess.run(["icacls", str(CONFIG), "/inheritance:r", "/grant:r", "SYSTEM:F", "Administrators:F"], check=True)
    print("Đã lưu bộ kiểm tra mật khẩu (PBKDF2), không lưu mật khẩu rõ.")


def verify() -> None:
    if not CONFIG.exists():
        raise SystemExit("Chưa thiết lập mật khẩu quản trị ChildGuard.")
    data = json.loads(CONFIG.read_text(encoding="utf-8"))
    supplied = getpass.getpass("Mật khẩu quản trị ChildGuard: ")
    actual = _derive(supplied, bytes.fromhex(data["salt"]))
    if not hmac.compare_digest(actual, data["hash"]):
        raise SystemExit("Sai mật khẩu; thao tác bị từ chối.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("set-password", "stop", "start", "restart", "uninstall"))
    args = parser.parse_args()
    if args.action == "set-password":
        set_password()
        return
    if args.action != "start":
        verify()
    if args.action == "uninstall":
        subprocess.run(["sc.exe", "stop", "ChildGuardAgent"], check=False)
        subprocess.run([sys.executable, str(Path(__file__).with_name("windows_service.py")), "remove"], check=True)
    elif args.action == "restart":
        subprocess.run(["sc.exe", "stop", "ChildGuardAgent"], check=False)
        subprocess.run(["sc.exe", "start", "ChildGuardAgent"], check=True)
    else:
        subprocess.run(["sc.exe", args.action, "ChildGuardAgent"], check=True)


if __name__ == "__main__":
    main()

