"""Xác thực phụ huynh (Auth) — xem mục 6 trong Design.md.

POST /auth/login: Phụ huynh đăng nhập, trả về session token.
POST /auth/logout: Đăng xuất.
GET /auth/me: Lấy thông tin tài khoản phụ huynh hiện tại.
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app import models, schemas, security
from app.database import get_db
from app.deps import get_current_parent

router = APIRouter(tags=["auth"])


@router.post("/auth/register", response_model=schemas.ParentRegisterResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: schemas.ParentRegisterRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """Đăng ký tài khoản phụ huynh mới (POST /auth/register)."""
    email_clean = payload.email.strip().lower()
    if "@" not in email_clean or "." not in email_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Địa chỉ email không hợp lệ.",
        )

    is_valid, msg = security.validate_password_strength(payload.password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    existing = db.query(models.Parent).filter(models.Parent.email == email_clean).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email này đã được đăng ký trong hệ thống.",
        )

    now = datetime.utcnow()
    name = (payload.full_name or "").strip() or "Phụ huynh"
    parent = models.Parent(
        email=email_clean,
        password_hash=security.hash_password(payload.password),
        full_name=name,
        failed_login_attempts=0,
        created_at=now,
    )
    db.add(parent)
    db.flush()

    audit = models.AuditLog(
        actor_type="parent",
        actor_id=parent.id,
        action="parent_registered",
        detail_json=f'{{"email": "{parent.email}", "name": "{parent.full_name}"}}',
        created_at=now,
    )
    db.add(audit)
    db.commit()
    db.refresh(parent)

    token = security.create_parent_session(parent.id, hours=12)
    response.set_cookie(
        key="ogk_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=43200,
    )

    return schemas.ParentRegisterResponse(
        access_token=token,
        token_type="bearer",
        parent_id=parent.id,
        parent_email=parent.email,
        parent_name=parent.full_name,
        message="Đăng ký tài khoản phụ huynh thành công",
    )


@router.post("/auth/login", response_model=schemas.ParentLoginResponse)
def login(
    payload: schemas.ParentLoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """Đăng nhập phụ huynh bằng Email và Mật khẩu (khóa tạm 15 phút sau 5 lần sai)."""
    parent = (
        db.query(models.Parent)
        .filter(models.Parent.email == payload.email.strip().lower())
        .first()
    )
    if parent is None:
        raise HTTPException(status_code=401, detail="invalid_credentials")

    now = datetime.utcnow()
    # Kiểm tra khóa tài khoản theo chuẩn F5
    if parent.locked_until and parent.locked_until > now:
        remaining_sec = int((parent.locked_until - now).total_seconds())
        remaining_min = max(1, (remaining_sec + 59) // 60)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Tài khoản đang bị tạm khóa an toàn. Vui lòng thử lại sau khoảng {remaining_min} phút.",
        )

    if not security.verify_password(payload.password, parent.password_hash):
        parent.failed_login_attempts += 1
        if parent.failed_login_attempts >= 5:
            parent.locked_until = now + timedelta(minutes=15)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Nhập sai mật khẩu 5 lần. Tài khoản bị tạm khóa 15 phút (theo NIST SP 800-63B).",
            )
        db.commit()
        raise HTTPException(status_code=401, detail="invalid_credentials")

    # Reset số lần đăng nhập sai
    parent.failed_login_attempts = 0
    parent.locked_until = None
    token = security.create_parent_session(parent.id, hours=12)

    audit = models.AuditLog(
        actor_type="parent",
        actor_id=parent.id,
        action="parent_login",
        detail_json=f'{{"email": "{parent.email}"}}',
        created_at=now,
    )
    db.add(audit)
    db.commit()

    # Set cookie cho trình duyệt web dashboard (hạn 12h theo F5)
    response.set_cookie(
        key="ogk_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=43200,
    )

    return schemas.ParentLoginResponse(
        access_token=token,
        token_type="bearer",
        parent_email=parent.email,
        parent_name=parent.full_name or "Phụ huynh",
    )

@router.post("/auth/refresh")
def refresh_device_token(request: Request, db: Session = Depends(get_db)):
    """Cấp lại access_token ngắn hạn cho Agent bằng refresh_token."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing_refresh_token")
    
    refresh_token = auth_header.removeprefix("Bearer ").strip()
    token_hash = security.hash_token(refresh_token)
    
    # Tìm token trong database
    token_record = db.query(models.Token).filter(
        models.Token.refresh_token_hash == token_hash,
        models.Token.revoked == False
    ).first()

    if not token_record:
        raise HTTPException(status_code=401, detail="invalid_or_revoked_refresh_token")

    # Sinh access_token mới (TTL 15 phút)
    new_access_token = security.create_device_access_token(token_record.device_id)
    token_record.access_token_hash = security.hash_token(new_access_token)
    # Cập nhật thời gian hết hạn mới cho access_token trong database nếu bảng Token có trường expires_at
    # token_record.access_expires_at = datetime.utcnow() + timedelta(minutes=15)
    
    db.commit()

    return {"access_token": new_access_token, "token_type": "bearer"}


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
