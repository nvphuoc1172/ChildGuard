from datetime import datetime, timedelta

from app import models, security


def _create_device(db_session):
    parent = models.Parent(email="p_req@test.local", password_hash="dummy")
    db_session.add(parent)
    db_session.flush()

    child = models.Child(parent_id=parent.id, display_name="Bé Hoa")
    db_session.add(child)
    db_session.flush()

    device = models.Device(
        child_id=child.id,
        fingerprint_hash="fprequest123",
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


def test_create_and_approve_child_request(client, db_session):
    device, token = _create_device(db_session)

    # 1. Trẻ gửi yêu cầu xin thêm 30 phút
    res = client.post(
        "/requests",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "request_type": "grant_time",
            "subject": "30",
            "reason": "Con cần làm bài tập thêm",
        },
    )
    assert res.status_code == 201
    req_data = res.json()
    assert req_data["status"] == "pending"
    req_id = req_data["id"]

    # 2. Phụ huynh xem danh sách
    res_list = client.get("/requests")
    assert res_list.status_code == 200
    assert any(r["id"] == req_id for r in res_list.json())

    # 3. Phụ huynh phê duyệt
    res_act = client.post(
        f"/requests/{req_id}/action",
        json={"action": "approve", "minutes": 30},
    )
    assert res_act.status_code == 200
    assert res_act.json()["status"] == "approved"

    # 4. Kiểm tra đã tự động tạo Command grant_minutes cho device
    cmd = (
        db_session.query(models.Command)
        .filter(models.Command.device_id == device.id, models.Command.command_type == "grant_minutes")
        .first()
    )
    assert cmd is not None
    assert "30" in cmd.payload_json


def test_reject_child_request(client, db_session):
    device, token = _create_device(db_session)

    res = client.post(
        "/requests",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "request_type": "grant_time",
            "subject": "15",
            "reason": "Chơi game",
        },
    )
    req_id = res.json()["id"]

    res_act = client.post(
        f"/requests/{req_id}/action",
        json={"action": "reject"},
    )
    assert res_act.status_code == 200
    assert res_act.json()["status"] == "rejected"
