"""Các hàm sinh mã/token và băm dùng trong luồng ghép đôi.

Không phụ thuộc framework — để test độc lập dễ dàng (xem tests/test_enroll.py).
"""
import hashlib
import secrets
from datetime import datetime, timedelta

# Bỏ các ký tự dễ nhầm khi đọc qua điện thoại: 0/O, 1/I/L
ENROLLMENT_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
ENROLLMENT_CODE_LENGTH = 8
ENROLLMENT_CODE_TTL_MINUTES = 10

ACCESS_TOKEN_TTL_MINUTES = 15
REFRESH_TOKEN_TTL_DAYS = 30


def generate_enrollment_code() -> str:
    """Sinh mã ghép đôi 8 ký tự, không phân biệt hoa/thường khi nhập
    (luôn lưu dạng in hoa)."""
    return "".join(secrets.choice(ENROLLMENT_CODE_ALPHABET) for _ in range(ENROLLMENT_CODE_LENGTH))


def enrollment_code_expiry(now: datetime | None = None) -> datetime:
    now = now or datetime.utcnow()
    return now + timedelta(minutes=ENROLLMENT_CODE_TTL_MINUTES)


def generate_raw_token() -> str:
    """Token ngẫu nhiên, an toàn mật mã học — trả về cho client dạng thô
    (chỉ tồn tại ở bước này, server chỉ lưu bản băm)."""
    return secrets.token_urlsafe(32)


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def access_token_expiry(now: datetime | None = None) -> datetime:
    now = now or datetime.utcnow()
    return now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)


def refresh_token_expiry(now: datetime | None = None) -> datetime:
    now = now or datetime.utcnow()
    return now + timedelta(days=REFRESH_TOKEN_TTL_DAYS)


def generate_matrix_from_times(start_time: str = "07:00", end_time: str = "21:30") -> list[list[int]]:
    """Tạo ma trận 7x48 mặc định từ start_time và end_time (độ phân giải 30 phút)."""
    try:
        sh, sm = map(int, start_time.split(":"))
        eh, em = map(int, end_time.split(":"))
        start_slot = sh * 2 + (1 if sm >= 30 else 0)
        end_slot = eh * 2 + (1 if em >= 30 else 0)
    except Exception:
        start_slot = 14  # 07:00
        end_slot = 43    # 21:30

    row = []
    for slot in range(48):
        if start_slot <= end_slot:
            allowed = 1 if (start_slot <= slot < end_slot) else 0
        else:
            allowed = 1 if (slot >= start_slot or slot < end_slot) else 0
        row.append(allowed)

    return [list(row) for _ in range(7)]


def validate_or_normalize_matrix(raw: any) -> list[list[int]] | None:
    """Kiểm tra và chuẩn hóa ma trận 7x48 (chỉ chứa 0 và 1)."""
    if not isinstance(raw, list) or len(raw) != 7:
        return None
    matrix = []
    for row in raw:
        if not isinstance(row, list) or len(row) != 48:
            return None
        matrix.append([1 if bool(cell) else 0 for cell in row])
    return matrix


def default_policy_payload() -> dict:
    """Chính sách mặc định khi một trẻ chưa từng có policy nào —
    an toàn-trước (quota thấp, không whitelist ứng dụng/domain nào),
    phụ huynh chỉnh lại ngay trên dashboard sau khi ghép đôi."""
    return {
        "quota_json": '{"daily_minutes": 120}',
        "schedule_json": "{}",
        "app_rules_json": '{"mode": "allow_all"}',
        "domain_rules_json": '{"mode": "allow_all"}',
    }


def hash_password(password: str, salt: str = "ogk-parent-salt") -> str:
    return hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()


import hmac
import time

SESSION_SECRET = "ogk-parent-secret-lab-2026-safe"


def verify_password(password: str, hashed: str, salt: str = "ogk-parent-salt") -> bool:
    """Xác minh mật khẩu bằng so sánh an toàn constant-time tránh timing attack."""
    if not password or not hashed:
        return False
    computed = hash_password(password, salt=salt)
    return hmac.compare_digest(computed, hashed)


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Kiểm tra độ mạnh mật khẩu theo NIST SP 800-63B và đề bài F5 (tối thiểu 10 ký tự)."""
    if not password or len(password) < 10:
        return False, "Mật khẩu phải có tối thiểu 10 ký tự (theo NIST SP 800-63B và chuẩn F5)."
    return True, ""


def create_parent_session(parent_id: str, hours: int = 12) -> str:
    """Tạo session token cho phụ huynh có chữ ký HMAC (hạn 12 giờ theo F5)."""
    expires = int(time.time()) + (hours * 3600)
    msg = f"{parent_id}:{expires}"
    sig = hmac.new(SESSION_SECRET.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{msg}:{sig}"


def verify_parent_session(session_token: str) -> str | None:
    try:
        parts = session_token.split(":")
        if len(parts) != 3:
            return None
        parent_id, expires_str, sig = parts
        expires = int(expires_str)
        if time.time() > expires:
            return None
        expected = hmac.new(
            SESSION_SECRET.encode("utf-8"),
            f"{parent_id}:{expires_str}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if hmac.compare_digest(sig, expected):
            return parent_id
        return None
    except Exception:
        return None


def _extract_base_filename(p: str) -> str:
    """Trích xuất tên file thực thi hỗ trợ cả đường dẫn Windows (\\) và Unix (/)."""
    return p.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()


def parse_app_rule_entry(entry: str | dict) -> dict:
    """Chuẩn hóa mục quy tắc ứng dụng hỗ trợ đối chiếu SHA-256.

    Hỗ trợ:
      - "game.exe"
      - "game.exe:a3c5...64hex..."
      - "C:\\Path\\game.exe:a3c5..."
      - "game.exe a3c5..."
      - "a3c5...64hex..." (chỉ có sha256)
      - {"name": "game.exe", "sha256": "a3c5..."}
    Trả về dict: {"name": str | None, "sha256": str | None}
    """
    from pathlib import Path

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

    # Chỉ có tên file
    return {"name": _extract_base_filename(entry_str), "sha256": None}



