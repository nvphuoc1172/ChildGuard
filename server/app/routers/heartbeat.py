"""POST /heartbeat, GET /policy — xem mục 5.2 trong docs/ChildGuard-Design.md.

Ghi chú quan trọng (đọc trước khi sửa): WebSocket lệnh khẩn (mục 5.3)
CHƯA được xây dựng ở tính năng này. Vì vậy hiện tại MỌI lệnh (lock/
unlock/grant_minutes) đều được giao qua heartbeat — đúng vai trò "kênh
dự phòng" đã thiết kế, chỉ khác là tạm thời nó là kênh DUY NHẤT. Khi
thêm WS /ws/{device_id}, heartbeat vẫn giữ nguyên logic này mà không
cần sửa gì — WS chỉ làm cho lệnh tới nhanh hơn (<5s thay vì chờ tới
heartbeat kế tiếp).
"""
import json
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db
from app.policy_rules import normalize_app_rules
from app.deps import get_current_device

router = APIRouter(tags=["heartbeat"])
LOCAL_TIMEZONE = ZoneInfo("Asia/Ho_Chi_Minh")


def _latest_policy(db: Session, child_id: str) -> models.Policy | None:
    return (
        db.query(models.Policy)
        .filter(models.Policy.child_id == child_id)
        .order_by(models.Policy.version.desc())
        .first()
    )


@router.post("/heartbeat", response_model=schemas.HeartbeatResponse)
def heartbeat(
    payload: schemas.HeartbeatRequest,
    device: models.Device = Depends(get_current_device),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    device.last_seen_at = now

    # quota_used_seconds là số liệu authoritative giống hệt mục "Đã dùng" ở
    # TrayUI. Chỉ ghi phần tăng thêm để giữ biểu đồ lịch sử mà không nhân đôi.
    quota_date = datetime.now(LOCAL_TIMEZONE).date().isoformat()
    previous = device.quota_used_seconds if device.quota_date == quota_date else 0
    current = payload.quota_used_seconds
    delta = max(0, current - previous)
    if delta:
        db.add(models.EventLog(
            idempotency_key=f"heartbeat-{device.id}-{quota_date}-{current}-{uuid.uuid4().hex[:8]}",
            device_id=device.id,
            child_id=device.child_id,
            event_type="screen_time",
            duration_sec=delta,
            policy_version=payload.policy_version,
            created_at=now,
        ))
    device.quota_date = quota_date
    device.quota_used_seconds = current

    latest_policy = _latest_policy(db, device.child_id)
    # Trường hợp lý thuyết: child chưa từng có policy (không nên xảy ra vì
    # /enroll luôn tạo policy v1) — fallback về đúng version agent đang có
    # để không báo "có thay đổi" một cách sai lệch.
    latest_version = latest_policy.version if latest_policy else payload.policy_version
    policy_changed = latest_version != payload.policy_version

    pending = (
        db.query(models.Command)
        .filter(models.Command.device_id == device.id, models.Command.delivered_at.is_(None))
        .order_by(models.Command.created_at.asc())
        .all()
    )

    out_commands = []
    for cmd in pending:
        cmd.delivered_at = now  # đánh dấu đã giao — không gửi lại ở heartbeat sau
        out_commands.append(
            schemas.PendingCommandOut(
                command_id=cmd.id,
                type=cmd.command_type,
                payload=json.loads(cmd.payload_json),
            )
        )

    db.commit()

    return schemas.HeartbeatResponse(
        policy_version=latest_version,
        policy_changed=policy_changed,
        pending_commands=out_commands,
        server_time=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        server_timestamp=now.timestamp(),
    )


@router.get("/policy", response_model=schemas.PolicyOut)
def get_policy(
    since_version: int = Query(default=0, ge=0),
    device: models.Device = Depends(get_current_device),
    db: Session = Depends(get_db),
):
    latest_policy = _latest_policy(db, device.child_id)
    if latest_policy is None:
        raise HTTPException(status_code=404, detail="no_policy_found")

    # since_version chỉ mang tính tham khảo/logging ở bản này — server luôn
    # trả về bản mới nhất, agent tự so sánh version để quyết định áp dụng
    # hay bỏ qua. Giữ tham số lại vì agent (heartbeat.py) đã gọi đúng cú
    # pháp này theo đặc tả, tránh phải sửa 2 lần khi có logic phức tạp hơn.
    return schemas.PolicyOut(
        version=latest_policy.version,
        quota=json.loads(latest_policy.quota_json),
        schedule=json.loads(latest_policy.schedule_json),
        app_rules=normalize_app_rules(json.loads(latest_policy.app_rules_json)),
        domain_rules=json.loads(latest_policy.domain_rules_json),
    )
