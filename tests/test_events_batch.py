import uuid
from datetime import datetime, timedelta

from app import models, security


def _create_device(db_session):
    parent = models.Parent(email="p_ev@test.local", password_hash="dummy")
    db_session.add(parent)
    db_session.flush()

    child = models.Child(parent_id=parent.id, display_name="Bé Bình")
    db_session.add(child)
    db_session.flush()

    device = models.Device(
        child_id=child.id,
        fingerprint_hash="fp9999999999",
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
        access_expires_at=now + timedelta(minutes=15),
        refresh_expires_at=now + timedelta(days=30),
        revoked=False,
    )
    db_session.add(token)
    db_session.commit()
    return device, raw_token


def test_batch_events_success(client, db_session):
    device, token = _create_device(db_session)
    events = [
        {
            "idempotency_key": "k1_" + uuid.uuid4().hex,
            "event_type": "screen_time",
            "duration_sec": 60,
        },
        {
            "idempotency_key": "k2_" + uuid.uuid4().hex,
            "event_type": "app_blocked",
            "subject": "game.exe",
            "duration_sec": 0,
        },
        {
            "idempotency_key": "k3_" + uuid.uuid4().hex,
            "event_type": "web_blocked",
            "subject": "tiktok.com",
            "duration_sec": 0,
        },
    ]

    res = client.post(
        "/events/batch",
        headers={"Authorization": f"Bearer {token}"},
        json={"events": events},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["processed"] == 3
    assert data["ignored"] == 0

    # Kiểm tra trong DB
    logs = db_session.query(models.EventLog).filter(models.EventLog.device_id == device.id).all()
    assert len(logs) == 3


def test_batch_events_idempotency_deduplication(client, db_session):
    device, token = _create_device(db_session)
    dup_key = "dup_key_" + uuid.uuid4().hex
    events = [
        {
            "idempotency_key": dup_key,
            "event_type": "screen_time",
            "duration_sec": 60,
        }
    ]

    # Lần 1: gửi thành công
    res1 = client.post(
        "/events/batch",
        headers={"Authorization": f"Bearer {token}"},
        json={"events": events},
    )
    assert res1.status_code == 200
    assert res1.json()["processed"] == 1
    assert res1.json()["ignored"] == 0

    # Lần 2: gửi lại cùng idempotency_key (giả lập agent gửi lại do rớt mạng)
    res2 = client.post(
        "/events/batch",
        headers={"Authorization": f"Bearer {token}"},
        json={"events": events},
    )
    assert res2.status_code == 200
    assert res2.json()["processed"] == 0
    assert res2.json()["ignored"] == 1

    # Kiểm tra trong DB chỉ có 1 bản ghi duy nhất
    logs = db_session.query(models.EventLog).filter(models.EventLog.idempotency_key == dup_key).all()
    assert len(logs) == 1
