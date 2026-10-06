"""Unit test cho POST /heartbeat và GET /policy.

Dùng chung fixture client/db_session với test_enroll.py (xem conftest.py).
Mỗi test tự ghép đôi một thiết bị qua chính endpoint /enroll thật (không
mock) để đảm bảo token sinh ra đúng luồng thật — nếu /enroll đổi hành vi,
test ở đây sẽ tự phát hiện breakage thay vì giả định ngầm.
"""
import json
from datetime import datetime, timedelta

from app import models


def _enroll_device(client, db_session, *, fingerprint="f" * 64):
    """Ghép đôi một thiết bị qua /enroll thật, trả về
    (device_id, access_token, policy_version)."""
    parent = models.Parent(email="hb-test@ogk.local", password_hash="x")
    db_session.add(parent)
    db_session.flush()

    child = models.Child(parent_id=parent.id, display_name="Bé Test")
    db_session.add(child)
    db_session.flush()

    enrollment = models.EnrollmentCode(
        code="HBTEST01",
        parent_id=parent.id,
        child_id=child.id,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db_session.add(enrollment)
    db_session.commit()

    resp = client.post("/enroll", json={"code": "HBTEST01", "device_fingerprint": fingerprint})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    return body["device_id"], body["access_token"], body["policy_version"], child.id


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------
# Nhóm 1 — xác thực token
# ---------------------------------------------------------------------


def test_heartbeat_without_token_returns_401(client, db_session):
    resp = client.post(
        "/heartbeat",
        json={"policy_version": 1, "quota_used_seconds": 0, "queued_event_count": 0},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "missing_bearer_token"


def test_heartbeat_with_garbage_token_returns_401(client, db_session):
    resp = client.post(
        "/heartbeat",
        json={"policy_version": 1, "quota_used_seconds": 0, "queued_event_count": 0},
        headers=_auth_headers("khong-phai-token-that"),
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_token"


def test_heartbeat_with_expired_token_returns_401(client, db_session):
    device_id, access_token, _, _ = _enroll_device(client, db_session)

    # Giả lập token đã hết hạn bằng cách chỉnh thẳng trong DB.
    token_row = db_session.query(models.Token).filter(models.Token.device_id == device_id).first()
    token_row.access_expires_at = datetime.utcnow() - timedelta(minutes=1)
    db_session.commit()

    resp = client.post(
        "/heartbeat",
        json={"policy_version": 1, "quota_used_seconds": 0, "queued_event_count": 0},
        headers=_auth_headers(access_token),
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "token_expired"


def test_heartbeat_with_revoked_token_returns_401(client, db_session):
    device_id, access_token, _, _ = _enroll_device(client, db_session)

    token_row = db_session.query(models.Token).filter(models.Token.device_id == device_id).first()
    token_row.revoked = True
    db_session.commit()

    resp = client.post(
        "/heartbeat",
        json={"policy_version": 1, "quota_used_seconds": 0, "queued_event_count": 0},
        headers=_auth_headers(access_token),
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "token_revoked"


# ---------------------------------------------------------------------
# Nhóm 2 — hành vi heartbeat thành công
# ---------------------------------------------------------------------


def test_heartbeat_success_updates_last_seen_at(client, db_session):
    device_id, access_token, policy_version, _ = _enroll_device(client, db_session)

    device = db_session.get(models.Device, device_id)
    old_last_seen = device.last_seen_at

    resp = client.post(
        "/heartbeat",
        json={"policy_version": policy_version, "quota_used_seconds": 10, "queued_event_count": 0},
        headers=_auth_headers(access_token),
    )
    assert resp.status_code == 200

    db_session.expire_all()
    device = db_session.get(models.Device, device_id)
    assert device.last_seen_at >= old_last_seen


def test_heartbeat_policy_changed_false_when_version_matches(client, db_session):
    _, access_token, policy_version, _ = _enroll_device(client, db_session)

    resp = client.post(
        "/heartbeat",
        json={"policy_version": policy_version, "quota_used_seconds": 0, "queued_event_count": 0},
        headers=_auth_headers(access_token),
    )
    body = resp.json()
    assert body["policy_changed"] is False
    assert body["policy_version"] == policy_version


def test_heartbeat_policy_changed_true_when_version_differs(client, db_session):
    _, access_token, policy_version, child_id = _enroll_device(client, db_session)

    # Phụ huynh "sửa chính sách" -> tạo bản Policy version mới.
    new_policy = models.Policy(
        child_id=child_id,
        version=policy_version + 1,
        quota_json='{"daily_minutes": 60}',
        schedule_json="{}",
        app_rules_json="{}",
        domain_rules_json="{}",
    )
    db_session.add(new_policy)
    db_session.commit()

    resp = client.post(
        "/heartbeat",
        json={"policy_version": policy_version, "quota_used_seconds": 0, "queued_event_count": 0},
        headers=_auth_headers(access_token),
    )
    body = resp.json()
    assert body["policy_changed"] is True
    assert body["policy_version"] == policy_version + 1


def test_heartbeat_returns_pending_command_and_marks_delivered(client, db_session):
    device_id, access_token, policy_version, _ = _enroll_device(client, db_session)

    command = models.Command(
        device_id=device_id,
        command_type="grant_minutes",
        payload_json=json.dumps({"minutes": 15}),
    )
    db_session.add(command)
    db_session.commit()

    resp = client.post(
        "/heartbeat",
        json={"policy_version": policy_version, "quota_used_seconds": 0, "queued_event_count": 0},
        headers=_auth_headers(access_token),
    )
    body = resp.json()
    assert len(body["pending_commands"]) == 1
    assert body["pending_commands"][0]["type"] == "grant_minutes"
    assert body["pending_commands"][0]["payload"] == {"minutes": 15}

    db_session.expire_all()
    updated_command = db_session.get(models.Command, command.id)
    assert updated_command.delivered_at is not None


def test_heartbeat_does_not_redeliver_already_delivered_command(client, db_session):
    device_id, access_token, policy_version, _ = _enroll_device(client, db_session)

    command = models.Command(
        device_id=device_id,
        command_type="lock",
        payload_json="{}",
        delivered_at=datetime.utcnow(),  # đã giao từ trước
    )
    db_session.add(command)
    db_session.commit()

    resp = client.post(
        "/heartbeat",
        json={"policy_version": policy_version, "quota_used_seconds": 0, "queued_event_count": 0},
        headers=_auth_headers(access_token),
    )
    assert resp.json()["pending_commands"] == []


# ---------------------------------------------------------------------
# Nhóm 3 — GET /policy
# ---------------------------------------------------------------------


def test_get_policy_without_token_returns_401(client, db_session):
    resp = client.get("/policy")
    assert resp.status_code == 401


def test_get_policy_returns_latest_version_and_parsed_json(client, db_session):
    _, access_token, policy_version, _ = _enroll_device(client, db_session)

    resp = client.get("/policy", headers=_auth_headers(access_token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == policy_version
    assert body["quota"] == {"daily_minutes": 120}  # default_policy_payload() trong security.py
