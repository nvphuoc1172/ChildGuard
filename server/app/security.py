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
