"""OGK-Agent — ghép đôi thiết bị (enrollment).

Chạy trên Windows 10/11:
    cd agent
    .\\.venv\\Scripts\\Activate.ps1
    python enroll.py --server 10.11.0.55 --ca-cert certs\\ogk-ca.crt

Script sẽ:
  1. Tính device fingerprint từ Machine GUID + hostname (không gửi dữ
     liệu định danh thô ra ngoài máy — xem mục 5.1 trong Design.md).
  2. Hỏi mã ghép đôi (8 ký tự) đã lấy từ server.
  3. Gọi POST /enroll qua HTTPS, xác minh server bằng CA nội bộ.
  4. Lưu device_id + token vào file JSON cục bộ.

Lưu ý: đây là bản dev chạy tay để test luồng ghép đôi. Khi làm tính
năng Windows Service, bước này sẽ chuyển thành một phần của quá trình
cài đặt (installer gọi enroll() rồi mới start service).
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:
    import winreg
except ImportError:  # pragma: no cover - chỉ chạy thật trên Windows
    winreg = None


def get_machine_guid() -> str:
    """Đọc Machine GUID từ registry Windows — ổn định qua các lần cài
    lại hệ điều hành khác nhau (không đổi trừ khi cài lại Windows)."""
    if winreg is None:
        # Cho phép chạy thử trên Linux/macOS khi phát triển/test logic,
        # không dùng để ghép đôi thật.
        return "dev-fake-machine-guid"
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
        ) as key:
            return winreg.QueryValueEx(key, "MachineGuid")[0]
    except OSError as exc:
        raise RuntimeError(
            "Không đọc được Machine GUID — thử chạy PowerShell với quyền "
            "Administrator."
        ) from exc


def compute_fingerprint() -> str:
    """fingerprint = SHA256(machine_guid:hostname) — tối giản dữ liệu,
    không thu thập gì khác (đúng tinh thần Nghị định 13/2023)."""
    guid = get_machine_guid()
    hostname = socket.gethostname()
    raw = f"{guid}:{hostname}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def call_enroll(server: str, port: int, ca_cert: str, code: str, fingerprint: str) -> dict:
    url = f"https://{server}:{port}/enroll"
    body = json.dumps({"code": code, "device_fingerprint": fingerprint}).encode("utf-8")

    ctx = ssl.create_default_context(cafile=ca_cert)
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(error_body).get("detail", error_body)
        except json.JSONDecodeError:
            detail = error_body
        raise SystemExit(f"Server từ chối ghép đôi ({exc.code}): {detail}")
    except urllib.error.URLError as exc:
        raise SystemExit(
            f"Không kết nối được tới {url} — kiểm tra lại IP server, "
            f"cổng, port-forward và chứng chỉ CA.\nChi tiết: {exc.reason}"
        )


def save_state(out_path: Path, state: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", required=True, help="IP của máy chủ (vd 10.11.0.55)")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--ca-cert", required=True, help="Đường dẫn tới ogk-ca.crt")
    parser.add_argument("--code", help="Mã ghép đôi (nếu bỏ qua, script sẽ hỏi)")
    parser.add_argument(
        "--out",
        default="agent_state/device_token.json",
        help="Nơi lưu device_id + token (mặc định: agent_state/device_token.json)",
    )
    args = parser.parse_args()

    code = args.code or input("Nhập mã ghép đôi (8 ký tự): ").strip().upper()
    if len(code) != 8:
        raise SystemExit("Mã ghép đôi phải có đúng 8 ký tự.")

    print("Đang tính device fingerprint...")
    fingerprint = compute_fingerprint()
    print(f"  fingerprint = {fingerprint[:16]}... (đã băm, không gửi dữ liệu thô)")

    print(f"Đang gọi POST https://{args.server}:{args.port}/enroll ...")
    result = call_enroll(args.server, args.port, args.ca_cert, code, fingerprint)

    out_path = Path(args.out)
    save_state(
        out_path,
        {
            "device_id": result["device_id"],
            "access_token": result["access_token"],
            "refresh_token": result["refresh_token"],
            "policy_version": result["policy_version"],
            "server": args.server,
            "port": args.port,
        },
    )

    print()
    print("Ghép đôi thành công.")
    print(f"  device_id      = {result['device_id']}")
    print(f"  policy_version = {result['policy_version']}")
    print(f"  Đã lưu token vào: {out_path.resolve()}")
    print()
    print("Lưu ý bảo mật: file này chứa token thật — không commit vào Git")
    print("(đã có trong .gitignore qua pattern *.json trong agent_state/).")


if __name__ == "__main__":
    main()
