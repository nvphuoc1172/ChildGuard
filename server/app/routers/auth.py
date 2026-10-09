"""Xác thực phụ huynh (Auth) — xem mục 6 trong Design.md.

POST /auth/login: Phụ huynh đăng nhập, trả về session token.
POST /auth/logout: Đăng xuất.
GET /auth/me: Lấy thông tin tài khoản phụ huynh hiện tại.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app import models, schemas, security
from app.database import get_db
from app.deps import get_current_parent

router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=schemas.ParentLoginResponse)
def login(
    payload: schemas.ParentLoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """Đăng nhập phụ huynh bằng Email và Mật khẩu."""
    parent = (
        db.query(models.Parent)
        .filter(models.Parent.email == payload.email.strip().lower())
        .first()
    )
    if parent is None:
        raise HTTPException(status_code=401, detail="invalid_credentials")

    if not security.verify_password(payload.password, parent.password_hash):
        parent.failed_login_attempts += 1
        db.commit()
        raise HTTPException(status_code=401, detail="invalid_credentials")

    # Reset số lần đăng nhập sai
    parent.failed_login_attempts = 0
    token = security.create_parent_session(parent.id)
    db.commit()

    # Set cookie cho trình duyệt web dashboard
    response.set_cookie(
        key="ogk_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=86400,
    )

    return schemas.ParentLoginResponse(
        access_token=token,
        token_type="bearer",
        parent_email=parent.email,
        parent_name=parent.full_name or "Phụ huynh",
    )


@router.post("/auth/logout")
def logout(response: Response):
    """Đăng xuất phụ huynh và xóa cookie phiên."""
    response.delete_cookie(key="ogk_session")
    return {"status": "ok"}


@router.get("/auth/me")
def get_me(parent: models.Parent = Depends(get_current_parent)):
    """Lấy thông tin tài khoản phụ huynh."""
    return {
        "id": parent.id,
        "email": parent.email,
        "full_name": parent.full_name,
        "created_at": parent.created_at.isoformat(),
    }
