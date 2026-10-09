import json

from app import models


def test_update_policy_increments_version(client, db_session):
    parent = models.Parent(email="p_pol@test.local", password_hash="dummy")
    db_session.add(parent)
    db_session.flush()

    child = models.Child(parent_id=parent.id, display_name="Bé Cường")
    db_session.add(child)
    db_session.flush()

    policy1 = models.Policy(
        child_id=child.id,
        version=1,
        quota_json='{"daily_minutes": 60}',
        schedule_json="{}",
        app_rules_json='{"mode": "allow_all"}',
        domain_rules_json='{"mode": "allow_all"}',
    )
    db_session.add(policy1)
    db_session.commit()

    # Cập nhật policy mới
    res = client.post(
        "/policy",
        json={
            "child_id": child.id,
            "quota": {"daily_minutes": 90},
            "schedule": {"active_hours": "08:00-20:00"},
            "app_rules": {"blacklist": ["game.exe"]},
            "domain_rules": {"blacklist": ["tiktok.com"]},
        },
    )
    assert res.status_code == 201
    data = res.json()
    assert data["version"] == 2
    assert data["quota"]["daily_minutes"] == 90
    assert data["app_rules"]["blacklist"] == ["game.exe"]

    # Kiểm tra AuditLog
    audit = db_session.query(models.AuditLog).filter(models.AuditLog.action == "policy_updated").first()
    assert audit is not None


def test_get_child_policy(client, db_session):
    parent = models.Parent(email="p_pol2@test.local", password_hash="dummy")
    db_session.add(parent)
    db_session.flush()

    child = models.Child(parent_id=parent.id, display_name="Bé Dũng")
    db_session.add(child)
    db_session.flush()

    policy = models.Policy(
        child_id=child.id,
        version=3,
        quota_json='{"daily_minutes": 120}',
        schedule_json="{}",
        app_rules_json='{"blacklist": ["roblox.exe"]}',
        domain_rules_json='{"blacklist": ["youtube.com"]}',
    )
    db_session.add(policy)
    db_session.commit()

    res = client.get(f"/policy/child/{child.id}")
    assert res.status_code == 200
    assert res.json()["version"] == 3
    assert res.json()["app_rules"]["blacklist"] == ["roblox.exe"]
