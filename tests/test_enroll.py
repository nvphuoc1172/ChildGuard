"""Unit test cho tính năng Ghép đôi (enrollment) — server/app/routers/enroll.py
và server/app/security.py.

Chạy: cd tests && pytest test_enroll.py -v
(hoặc từ gốc repo: pytest tests/ -v)
"""
import json
from datetime import datetime, timedelta

from app import models, security


# ---------------------------------------------------------------------
# Nhóm 1 — security.py (logic thuần, không cần DB/HTTP)
# ---------------------------------------------------------------------


def test_generate_enrollment_code_has_correct_length():
    code = security.generate_enrollment_code()
    assert len(code) == security.ENROLLMENT_CODE_LENGTH == 8


def test_generate_enrollment_code_excludes_ambiguous_characters():
    # Sinh nhiều mã để kiểm tra không ký tự nào nằm ngoài bảng chữ cái
    # đã loại 0/O, 1/I/L — tránh phụ huynh đọc nhầm qua điện thoại.
    ambiguous = set("0O1IL")
    for _ in range(200):
        code = security.generate_enrollment_code()
        assert not (set(code) & ambiguous), f"Mã {code} chứa ký tự dễ nhầm"


def test_generate_enrollment_code_is_reasonably_unique():
    codes = {security.generate_enrollment_code() for _ in range(500)}
    # Với bảng 32 ký tự ^ 8 vị trí, 500 mẫu trùng nhau gần như không thể
    # xảy ra trừ khi logic sinh mã bị lỗi (vd luôn trả về hằng số).
    assert len(codes) == 500


def test_hash_token_is_deterministic():
    raw = "abc123"
    assert security.hash_token(raw) == security.hash_token(raw)


def test_hash_token_differs_for_different_inputs():
    assert security.hash_token("token-a") != security.hash_token("token-b")


def test_hash_token_never_returns_the_raw_value():
    raw = "super-secret-token"
    assert security.hash_token(raw) != raw


def test_generate_raw_token_is_sufficiently_random():
    tokens = {security.generate_raw_token() for _ in range(100)}
    assert len(tokens) == 100


def test_access_token_ttl_shorter_than_refresh_token_ttl():
    now = datetime.utcnow()
    access_exp = security.access_token_expiry(now)
    refresh_exp = security.refresh_token_expiry(now)
    assert access_exp < refresh_exp


def test_enrollment_code_expiry_is_ten_minutes_from_now():
    now = datetime.utcnow()
    expiry = security.enrollment_code_expiry(now)
    delta = expiry - now
    assert timedelta(minutes=9, seconds=59) <= delta <= timedelta(minutes=10, seconds=1)


def test_default_policy_payload_has_required_keys():
    payload = security.default_policy_payload()
    for key in ("quota_json", "schedule_json", "app_rules_json", "domain_rules_json"):
        assert key in payload
        json.loads(payload[key])  # phải là JSON hợp lệ


# ---------------------------------------------------------------------
# Nhóm 2 — POST /enroll (qua TestClient, dùng DB tạm từ fixture)
# ---------------------------------------------------------------------


def _seed_enrollment_code(db_session, *, expires_in_minutes=10, used=False):
    parent = models.Parent(email="demo@ogk.local", password_hash="x")
    db_session.add(parent)
    db_session.flush()

    child = models.Child(parent_id=parent.id, display_name="Minh An")
    db_session.add(child)
    db_session.flush()

    enrollment = models.EnrollmentCode(
        code="ABCD2345",
        parent_id=parent.id,
        child_id=child.id,
        expires_at=datetime.utcnow() + timedelta(minutes=expires_in_minutes),
        used_at=datetime.utcnow() if used else None,
    )
    db_session.add(enrollment)
    db_session.commit()
    return parent, child, enrollment


def test_enroll_success_returns_device_and_tokens(client, db_session):
    _seed_enrollment_code(db_session)

    resp = client.post(
        "/enroll",
        json={"code": "ABCD2345", "device_fingerprint": "f" * 64},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["device_id"]
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["policy_version"] == 1


def test_enroll_creates_device_row_in_db(client, db_session):
    _, child, _ = _seed_enrollment_code(db_session)

    client.post("/enroll", json={"code": "ABCD2345", "device_fingerprint": "f" * 64})

    device = db_session.query(models.Device).filter(models.Device.child_id == child.id).first()
    assert device is not None
    assert device.fingerprint_hash == "f" * 64
    assert device.status == "active"


def test_enroll_creates_default_policy_version_1(client, db_session):
    _, child, _ = _seed_enrollment_code(db_session)

    client.post("/enroll", json={"code": "ABCD2345", "device_fingerprint": "f" * 64})

    policy = db_session.query(models.Policy).filter(models.Policy.child_id == child.id).first()
    assert policy is not None
    assert policy.version == 1


def test_enroll_does_not_create_duplicate_policy_if_one_exists(client, db_session):
    parent, child, _ = _seed_enrollment_code(db_session)
    # Giả lập trẻ đã có policy version 2 từ trước (vd phụ huynh từng cấu
    # hình, agent cài lại trên thiết bị mới)
    existing = models.Policy(
        child_id=child.id,
        version=2,
        quota_json="{}",
        schedule_json="{}",
        app_rules_json="{}",
        domain_rules_json="{}",
    )
    db_session.add(existing)
    db_session.commit()

    resp = client.post("/enroll", json={"code": "ABCD2345", "device_fingerprint": "f" * 64})

    assert resp.json()["policy_version"] == 2
    policies = db_session.query(models.Policy).filter(models.Policy.child_id == child.id).all()
    assert len(policies) == 1  # không tạo thêm bản ghi mới


def test_enroll_marks_code_as_used(client, db_session):
    _seed_enrollment_code(db_session)

    client.post("/enroll", json={"code": "ABCD2345", "device_fingerprint": "f" * 64})

    db_session.expire_all()
    enrollment = db_session.get(models.EnrollmentCode, "ABCD2345")
    assert enrollment.used_at is not None


def test_enroll_writes_audit_log_entry(client, db_session):
    _seed_enrollment_code(db_session)

    client.post("/enroll", json={"code": "ABCD2345", "device_fingerprint": "f" * 64})

    audit = (
        db_session.query(models.AuditLog)
        .filter(models.AuditLog.action == "enrollment_completed")
        .first()
    )
    assert audit is not None
    assert audit.actor_type == "agent"
    detail = json.loads(audit.detail_json)
    assert detail["code"] == "ABCD2345"


def test_enroll_with_unknown_code_returns_404(client, db_session):
    resp = client.post(
        "/enroll", json={"code": "ZZZZZZZZ", "device_fingerprint": "f" * 64}
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "invalid_code"


def test_enroll_with_expired_code_returns_410(client, db_session):
    _seed_enrollment_code(db_session, expires_in_minutes=-1)

    resp = client.post(
        "/enroll", json={"code": "ABCD2345", "device_fingerprint": "f" * 64}
    )
    assert resp.status_code == 410
    assert resp.json()["detail"] == "code_expired"


def test_enroll_with_already_used_code_returns_409(client, db_session):
    _seed_enrollment_code(db_session, used=True)

    resp = client.post(
        "/enroll", json={"code": "ABCD2345", "device_fingerprint": "f" * 64}
    )
    assert resp.status_code == 409
    assert resp.json()["detail"] == "code_already_used"


def test_enroll_same_code_twice_second_attempt_fails(client, db_session):
    _seed_enrollment_code(db_session)

    first = client.post("/enroll", json={"code": "ABCD2345", "device_fingerprint": "f" * 64})
    second = client.post("/enroll", json={"code": "ABCD2345", "device_fingerprint": "g" * 64})

    assert first.status_code == 201
    assert second.status_code == 409
