"""FastAPI dependency dùng chung: xác thực access token của agent.

Mọi endpoint agent gọi sau bước ghép đôi (heartbeat, policy, events,
commands/ack...) đều cần Authorization: Bearer <access_token> và đi qua
get_current_device() ở đây — viết một lần, dùng lại cho mọi tính năng
mới thay vì lặp lại logic kiểm tra token.
"""
from datetime import datetime

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app import models, security
from app.database import get_db


def get_current_device(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> models.Device:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="missing_bearer_token"
        )

    raw_token = authorization.removeprefix("Bearer ").strip()
    token_hash = security.hash_token(raw_token)

    token_row = (
        db.query(models.Token)
        .filter(models.Token.access_token_hash == token_hash)
        .first()
    )
    if token_row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_token")

    if token_row.revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token_revoked")

    if token_row.access_expires_at < datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token_expired")

    device = db.get(models.Device, token_row.device_id)
    if device is None or device.status != "active":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="device_not_active")

    return device