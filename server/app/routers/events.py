"""POST /events/batch — xem mục 5.4 trong Design.md.

Đồng bộ sự kiện hàng loạt từ Agent lên Server khi có mạng lại.
Có xử lý Idempotency Key chống đếm trùng thời gian sử dụng và log chặn.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db
from app.deps import get_current_device

router = APIRouter(tags=["events"])


@router.post("/events/batch", response_model=schemas.BatchEventsResponse)
def batch_events(
    payload: schemas.BatchEventsRequest,
    device: models.Device = Depends(get_current_device),
    db: Session = Depends(get_db),
):
    """Nhận lô sự kiện từ Agent và ghi vào EventLog với cơ chế deduplication theo idempotency_key."""
    processed = 0
    ignored = 0

    now = datetime.utcnow()
    device.last_seen_at = now

    for ev in payload.events:
        # Kiểm tra xem idempotency_key đã tồn tại chưa
        existing = (
            db.query(models.EventLog)
            .filter(models.EventLog.idempotency_key == ev.idempotency_key)
            .first()
        )
        if existing is not None:
            ignored += 1
            continue

        created_dt = now
        if ev.created_at:
            try:
                created_dt = datetime.fromisoformat(ev.created_at.replace("Z", "+00:00"))
            except Exception:
                created_dt = now

        log_entry = models.EventLog(
            idempotency_key=ev.idempotency_key,
            device_id=device.id,
            child_id=device.child_id,
            event_type=ev.event_type,
            subject=ev.subject,
            duration_sec=ev.duration_sec,
            policy_version=ev.policy_version,
            created_at=created_dt,
        )
        db.add(log_entry)
        try:
            db.flush()
            processed += 1
        except IntegrityError:
            db.rollback()
            ignored += 1

    db.commit()

    return schemas.BatchEventsResponse(processed=processed, ignored=ignored)
