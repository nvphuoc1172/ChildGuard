"""POST /enroll — xem mục 5.1 trong docs/ChildGuard-Design.md.

Bước này chính là điểm ghi nhận sự đồng ý của phụ huynh (consent),
nên MỌI lần gọi thành công đều phải ghi AuditLog — không bỏ qua dù
để tối ưu tốc độ.
"""
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import models, schemas, security
from app.database import get_db

router = APIRouter(tags=["enroll"])


@router.post(
    "/enroll",
    response_model=schemas.EnrollResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        404: {"model": schemas.ErrorResponse, "description": "Mã ghép đôi không tồn tại"},
        409: {"model": schemas.ErrorResponse, "description": "Mã ghép đôi đã được dùng"},
        410: {"model": schemas.ErrorResponse, "description": "Mã ghép đôi đã hết hạn"},
    },
)
def enroll_device(payload: schemas.EnrollRequest, db: Session = Depends(get_db)):
    code = payload.code.strip().upper()

    enrollment = db.get(models.EnrollmentCode, code)
    if enrollment is None:
        raise HTTPException(status_code=404, detail="invalid_code")

    now = datetime.utcnow()

    if enrollment.used_at is not None:
        raise HTTPException(status_code=409, detail="code_already_used")

    if enrollment.expires_at < now:
        raise HTTPException(status_code=410, detail="code_expired")

    # --- Tạo thiết bị mới ---
    device = models.Device(
        child_id=enrollment.child_id,
        fingerprint_hash=payload.device_fingerprint,
        enrolled_at=now,
        last_seen_at=now,
        status="active",
    )
    db.add(device)

    # --- Đánh dấu mã đã dùng (không xoá — giữ lại phục vụ audit) ---
    enrollment.used_at = now

    # --- Đảm bảo trẻ có policy mặc định (chỉ tạo nếu chưa có) ---
    latest_policy = (
        db.query(models.Policy)
        .filter(models.Policy.child_id == enrollment.child_id)
        .order_by(models.Policy.version.desc())
        .first()
    )
    if latest_policy is None:
        defaults = security.default_policy_payload()
        latest_policy = models.Policy(
            child_id=enrollment.child_id,
            version=1,
            quota_json=defaults["quota_json"],
            schedule_json=defaults["schedule_json"],
            app_rules_json=defaults["app_rules_json"],
            domain_rules_json=defaults["domain_rules_json"],
        )
        db.add(latest_policy)

    # --- Cấp cặp token ---
    raw_access = security.generate_raw_token()
    raw_refresh = security.generate_raw_token()
    token_row = models.Token(
        device_id=device.id,
        access_token_hash=security.hash_token(raw_access),
        refresh_token_hash=security.hash_token(raw_refresh),
        access_expires_at=security.access_token_expiry(now),
        refresh_expires_at=security.refresh_token_expiry(now),
        revoked=False,
    )
    db.add(token_row)

    # --- Ghi nhận sự đồng ý (bắt buộc) ---
    audit = models.AuditLog(
        actor_type="agent",
        actor_id=device.id,
        action="enrollment_completed",
        detail_json=json.dumps(
            {
                "code": code,
                "child_id": enrollment.child_id,
                "parent_id": enrollment.parent_id,
            }
        ),
        created_at=now,
    )
    db.add(audit)

    db.commit()
    db.refresh(device)

    return schemas.EnrollResponse(
        device_id=device.id,
        access_token=raw_access,
        refresh_token=raw_refresh,
        policy_version=latest_policy.version,
    )
