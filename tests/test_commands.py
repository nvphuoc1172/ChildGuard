from datetime import datetime, timedelta
import uuid

from app import models, security



def _create_device(db_session, expired=False, revoked=False):
    parent = models.Parent(email=f"p_{uuid.uuid4().hex[:8]}@test.local", password_hash="dummy")
    db_session.add(parent)
    db_session.flush()

    child = models.Child(parent_id=parent.id, display_name="Bé An")
    db_session.add(child)
    db_session.flush()

    device = models.Device(
        child_id=child.id,
        fingerprint_hash="fp1234567890abcdef",
        status="active",
    )
    db_session.add(device)
    db_session.flush()

    raw_token = security.generate_raw_token()
    now = datetime.utcnow()
    token = models.Token(
        device_id=device.id,
        access_token_hash=security.hash_token(raw_token),
        refresh_token_hash=security.hash_token(security.generate_raw_token()),
        access_expires_at=now + timedelta(minutes=15) if not expired else now - timedelta(minutes=1),
        refresh_expires_at=now + timedelta(days=30),
        revoked=revoked,
    )
    db_session.add(token)
    db_session.commit()
    return device, raw_token


def test_create_command_success(client, db_session):
    device, _ = _create_device(db_session)
    res = client.post(
        "/commands",
        json={"device_id": device.id, "command_type": "lock", "payload": {}},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["type"] == "lock"
    assert "command_id" in data

    # Kiểm tra trong DB
    cmd = db_session.get(models.Command, data["command_id"])
    assert cmd is not None
    assert cmd.command_type == "lock"
    assert cmd.device_id == device.id


def test_create_command_grant_minutes(client, db_session):
    device, _ = _create_device(db_session)
    res = client.post(
        "/commands",
        json={"device_id": device.id, "command_type": "grant_minutes", "payload": {"minutes": 30}},
    )
    assert res.status_code == 201
    assert res.json()["payload"]["minutes"] == 30


def test_create_command_invalid_device_returns_404(client):
    res = client.post(
        "/commands",
        json={"device_id": "nonexistent", "command_type": "lock", "payload": {}},
    )
    assert res.status_code == 404


def test_ack_command_success(client, db_session):
    device, token = _create_device(db_session)
    cmd = models.Command(
        device_id=device.id,
        command_type="lock",
        payload_json="{}",
    )
    db_session.add(cmd)
    db_session.commit()

    res = client.post(
        f"/commands/{cmd.id}/ack",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "ok"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

    # Kiểm tra trong DB
    db_session.refresh(cmd)
    assert cmd.acked_at is not None
    assert cmd.delivered_at is not None


def test_ack_command_wrong_device_returns_403(client, db_session):
    device1, _ = _create_device(db_session)
    device2, token2 = _create_device(db_session)

    cmd = models.Command(
        device_id=device1.id,
        command_type="lock",
        payload_json="{}",
    )
    db_session.add(cmd)
    db_session.commit()

    res = client.post(
        f"/commands/{cmd.id}/ack",
        headers={"Authorization": f"Bearer {token2}"},
        json={"status": "ok"},
    )
    assert res.status_code == 403
