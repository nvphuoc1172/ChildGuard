"""Quản lý Yêu cầu từ trẻ (Child Requests) — xin thêm giờ, báo cáo chặn nhầm.

- POST /requests: Agent gửi yêu cầu của trẻ lên Server.
- GET /requests: Danh sách yêu cầu (lọc theo pending / resolved).
- POST /requests/{id}/action: Phụ huynh duyệt (tự phát lệnh grant_minutes) hoặc từ chối.
"""
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db
from app.deps import get_current_device
from app.routers.commands import manager

router = APIRouter(tags=["requests"])


@router.post("/requests", response_model=schemas.ChildRequestOut, status_code=status.HTTP_201_CREATED)
def create_child_request(
    payload: schemas.ChildRequestCreate,
    device: models.Device = Depends(get_current_device),
    db: Session = Depends(get_db),
):
    """Agent gửi yêu cầu mới của trẻ lên Server."""
    now = datetime.utcnow()
    req = models.ChildRequest(
        child_id=device.child_id,
        device_id=device.id,
        request_type=payload.request_type,
        subject=payload.subject,
        reason=payload.reason,
        status="pending",
        created_at=now,
    )
    db.add(req)
    db.commit()
    db.refresh(req)

    return schemas.ChildRequestOut(
        id=req.id,
        child_id=req.child_id,
        device_id=req.device_id,
        request_type=req.request_type,
        subject=req.subject,
        reason=req.reason,
        status=req.status,
        created_at=req.created_at.isoformat(),
        resolved_at=None,
    )


@router.get("/requests", response_model=list[schemas.ChildRequestOut])
def list_child_requests(
    child_id: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
):
    """Danh sách các yêu cầu của trẻ."""
    query = db.query(models.ChildRequest)
    if child_id:
        query = query.filter(models.ChildRequest.child_id == child_id)
    if status_filter:
        query = query.filter(models.ChildRequest.status == status_filter)

    requests = query.order_by(models.ChildRequest.created_at.desc()).all()
    out = []
    for r in requests:
        out.append(
            schemas.ChildRequestOut(
                id=r.id,
                child_id=r.child_id,
                device_id=r.device_id,
                request_type=r.request_type,
                subject=r.subject,
                reason=r.reason,
                status=r.status,
                created_at=r.created_at.isoformat(),
                resolved_at=r.resolved_at.isoformat() if r.resolved_at else None,
            )
        )
    return out


@router.post("/requests/{request_id}/action", response_model=schemas.ChildRequestOut)
async def process_child_request(
    request_id: str,
    action_data: schemas.ChildRequestAction,
    db: Session = Depends(get_db),
):
    """Phụ huynh duyệt hoặc từ chối yêu cầu của trẻ.

    Nếu duyệt xin thêm giờ -> tự động tạo Command grant_minutes cho thiết bị.
    """
    req = db.get(models.ChildRequest, request_id)
    if req is None:
        raise HTTPException(status_code=404, detail="request_not_found")

    if req.status != "pending":
        raise HTTPException(status_code=400, detail="request_already_processed")

    now = datetime.utcnow()
    action = action_data.action.lower()
    if action not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="invalid_action")

    if action == "approve":
        req.status = "approved"
        # Nếu là xin thêm giờ -> tự phát sinh lệnh grant_minutes
        if req.request_type == "grant_time":
            try:
                minutes = int(req.subject) if req.subject and req.subject.isdigit() else (action_data.minutes or 15)
            except Exception:
                minutes = action_data.minutes or 15

            cmd = models.Command(
                device_id=req.device_id,
                command_type="grant_minutes",
                payload_json=json.dumps({"minutes": minutes}),
                created_at=now,
            )
            db.add(cmd)
            db.flush()

            # Đẩy ngay qua WebSocket nếu device đang online
            cmd_data = {
                "command_id": cmd.id,
                "type": cmd.command_type,
                "payload": {"minutes": minutes},
            }
            sent = await manager.send_command(req.device_id, cmd_data)
            if sent:
                cmd.delivered_at = now
    else:
        req.status = "rejected"

    req.resolved_at = now
    db.commit()
    db.refresh(req)

    return schemas.ChildRequestOut(
        id=req.id,
        child_id=req.child_id,
        device_id=req.device_id,
        request_type=req.request_type,
        subject=req.subject,
        reason=req.reason,
        status=req.status,
        created_at=req.created_at.isoformat(),
        resolved_at=req.resolved_at.isoformat() if req.resolved_at else None,
    )
