"""Quản lý Chính sách (Policy) — xem mục 4 và mục 6 trong Design.md.

Cho phép phụ huynh chỉnh sửa quota, lịch tuần, app rules, domain rules.
Mỗi lần sửa sẽ tăng version lên 1 để Agent tự động cập nhật khi heartbeat/ws.
"""
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db

router = APIRouter(tags=["policy"])


@router.post("/policy", response_model=schemas.PolicyOut, status_code=status.HTTP_201_CREATED)
def update_policy(
    payload: schemas.PolicyUpdateRequest,
    db: Session = Depends(get_db),
):
    """Tạo phiên bản chính sách mới cho một trẻ."""
    child = db.get(models.Child, payload.child_id)
    if child is None:
        raise HTTPException(status_code=404, detail="child_not_found")

    latest = (
        db.query(models.Policy)
        .filter(models.Policy.child_id == payload.child_id)
        .order_by(models.Policy.version.desc())
        .first()
    )
    new_version = (latest.version + 1) if latest else 1
    now = datetime.utcnow()

    new_policy = models.Policy(
        child_id=payload.child_id,
        version=new_version,
        quota_json=json.dumps(payload.quota),
        schedule_json=json.dumps(payload.schedule),
        app_rules_json=json.dumps(payload.app_rules),
        domain_rules_json=json.dumps(payload.domain_rules),
        created_at=now,
    )
    db.add(new_policy)

    # Ghi audit log
    audit = models.AuditLog(
        actor_type="parent",
        actor_id=child.parent_id,
        action="policy_updated",
        detail_json=json.dumps(
            {
                "child_id": child.id,
                "version": new_version,
                "quota": payload.quota,
            }
        ),
        created_at=now,
    )
    db.add(audit)
    db.commit()

    return schemas.PolicyOut(
        version=new_policy.version,
        quota=payload.quota,
        schedule=payload.schedule,
        app_rules=payload.app_rules,
        domain_rules=payload.domain_rules,
    )


@router.get("/policy/child/{child_id}", response_model=schemas.PolicyOut)
def get_child_policy(child_id: str, db: Session = Depends(get_db)):
    """Lấy phiên bản chính sách mới nhất của trẻ."""
    latest = (
        db.query(models.Policy)
        .filter(models.Policy.child_id == child_id)
        .order_by(models.Policy.version.desc())
        .first()
    )
    if latest is None:
        raise HTTPException(status_code=404, detail="policy_not_found")

    return schemas.PolicyOut(
        version=latest.version,
        quota=json.loads(latest.quota_json),
        schedule=json.loads(latest.schedule_json),
        app_rules=json.loads(latest.app_rules_json),
        domain_rules=json.loads(latest.domain_rules_json),
    )
