"""Router cho Giao diện Web phụ huynh (Parent Dashboard) — Jinja2 + HTMX.

Hỗ trợ:
- /dashboard: Trang tổng quan (overview)
- /dashboard/login: Đăng nhập phụ huynh
- /dashboard/policy: Quản lý chính sách (quota, app blacklist, domain blacklist, lịch)
- /dashboard/requests: Duyệt yêu cầu xin thêm giờ của trẻ
- /dashboard/reports: Thống kê báo cáo thời gian dùng và app/web bị chặn
- /dashboard/audit: Nhật ký kiểm toán
- /dashboard/action/command: Nút bấm phát lệnh khẩn cấp tức thì (Lock/Unlock/Grant)
- /dashboard/devices: Giữ nguyên route danh sách thiết bị
"""
import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app import models, security
from app.database import get_db
from app.deps import get_optional_parent
from app.routers.commands import manager
from app.routers.reports import cleanup_old_logs, get_child_stats_summary

router = APIRouter(tags=["dashboard"])

TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "dashboard" / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

ONLINE_THRESHOLD_SECONDS = 180


def _get_or_create_demo_parent(db: Session) -> models.Parent:
    parent = db.query(models.Parent).filter(models.Parent.email == "demo@ogk.local").first()
    if not parent:
        parent = models.Parent(
            email="demo@ogk.local",
            password_hash=security.hash_password("admin123"),
            full_name="Phụ huynh Demo",
            failed_login_attempts=0,
        )
        db.add(parent)
        db.commit()
        db.refresh(parent)
    else:
        if not security.verify_password("admin123", parent.password_hash):
            parent.password_hash = security.hash_password("admin123")
            db.commit()
    return parent


@router.get("/", response_class=RedirectResponse)
def root_redirect():
    """Chuyển hướng trang gốc về trang tổng quan phụ huynh."""
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)


@router.get("/dashboard/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    registered: int | None = None,
    logout: int | None = None,
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    """Trang đăng nhập phụ huynh."""
    if parent:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

    _get_or_create_demo_parent(db)
    success_msg = None
    if registered:
        success_msg = "Đăng ký tài khoản phụ huynh thành công! Mời bạn đăng nhập để tiếp tục."
    elif logout:
        success_msg = "Bạn đã đăng xuất thành công khỏi hệ thống."

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": None,
            "success": success_msg,
            "email": "",
        },
    )


@router.post("/dashboard/login", response_class=HTMLResponse)
def process_login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    """Xử lý đăng nhập phụ huynh với chính sách khóa tạm 15 phút sau 5 lần sai (F5)."""
    email_clean = email.strip().lower()
    parent = (
        db.query(models.Parent)
        .filter(models.Parent.email == email_clean)
        .first()
    )

    now = datetime.utcnow()
    if parent and parent.locked_until and parent.locked_until > now:
        remaining_sec = int((parent.locked_until - now).total_seconds())
        remaining_min = max(1, (remaining_sec + 59) // 60)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": f"Tài khoản đang bị tạm khóa an toàn do nhập sai 5 lần. Vui lòng thử lại sau khoảng {remaining_min} phút.",
                "email": email_clean,
                "success": None,
            },
            status_code=403,
        )

    if not parent or not security.verify_password(password, parent.password_hash):
        if parent:
            parent.failed_login_attempts += 1
            if parent.failed_login_attempts >= 5:
                parent.locked_until = now + timedelta(minutes=15)
                db.commit()
                return templates.TemplateResponse(
                    request=request,
                    name="login.html",
                    context={
                        "error": "Bạn đã nhập sai mật khẩu 5 lần. Tài khoản tạm khóa 15 phút (theo tiêu chuẩn NIST SP 800-63B & F5).",
                        "email": email_clean,
                        "success": None,
                    },
                    status_code=403,
                )
            db.commit()

        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Email hoặc mật khẩu không chính xác.",
                "email": email_clean,
                "success": None,
            },
            status_code=401,
        )

    # Đăng nhập thành công
    parent.failed_login_attempts = 0
    parent.locked_until = None
    token = security.create_parent_session(parent.id, hours=12)

    audit = models.AuditLog(
        actor_type="parent",
        actor_id=parent.id,
        action="dashboard_login",
        detail_json=f'{{"email": "{parent.email}"}}',
        created_at=now,
    )
    db.add(audit)
    db.commit()

    redirect = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(
        key="ogk_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=43200,  # 12 giờ
    )
    return redirect


@router.post("/dashboard/quick-demo-login")
def quick_demo_login(
    db: Session = Depends(get_db),
):
    """Nút đăng nhập nhanh 1 chạm bằng tài khoản demo để kiểm thử."""
    demo_parent = _get_or_create_demo_parent(db)
    demo_parent.failed_login_attempts = 0
    demo_parent.locked_until = None
    db.commit()

    token = security.create_parent_session(demo_parent.id, hours=12)
    redirect = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(
        key="ogk_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=43200,
    )
    return redirect


@router.get("/dashboard/register", response_class=HTMLResponse)
def register_page(
    request: Request,
    parent: models.Parent | None = Depends(get_optional_parent),
):
    """Giao diện đăng ký tài khoản phụ huynh."""
    if parent:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={
            "error": None,
            "form_data": {},
        },
    )


@router.post("/dashboard/register", response_class=HTMLResponse)
def process_register(
    request: Request,
    email: str = Form(...),
    full_name: str = Form(default=""),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
):
    """Xử lý đăng ký tài khoản phụ huynh (mật khẩu >= 10 ký tự, kiểm tra trùng lặp email)."""
    email_clean = email.strip().lower()
    name_clean = full_name.strip() or "Phụ huynh"
    form_data = {"email": email_clean, "full_name": full_name}

    if "@" not in email_clean or "." not in email_clean:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Địa chỉ email không hợp lệ.", "form_data": form_data},
            status_code=400,
        )

    if password != confirm_password:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Mật khẩu xác nhận không khớp với mật khẩu đã nhập.", "form_data": form_data},
            status_code=400,
        )

    is_valid, msg = security.validate_password_strength(password)
    if not is_valid:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": msg, "form_data": form_data},
            status_code=400,
        )

    existing = db.query(models.Parent).filter(models.Parent.email == email_clean).first()
    if existing:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "error": "Email này đã được sử dụng. Vui lòng đăng nhập hoặc dùng email khác.",
                "form_data": form_data,
            },
            status_code=400,
        )

    now = datetime.utcnow()
    new_parent = models.Parent(
        email=email_clean,
        full_name=name_clean,
        password_hash=security.hash_password(password),
        failed_login_attempts=0,
        created_at=now,
    )
    db.add(new_parent)
    db.flush()

    audit = models.AuditLog(
        actor_type="parent",
        actor_id=new_parent.id,
        action="dashboard_register",
        detail_json=f'{{"email": "{new_parent.email}", "name": "{new_parent.full_name}"}}',
        created_at=now,
    )
    db.add(audit)
    db.commit()
    db.refresh(new_parent)

    # Đăng ký thành công -> Chuyển về trang đăng nhập kèm thông báo
    return RedirectResponse(
        url="/dashboard/login?registered=1",
        status_code=status.HTTP_302_FOUND,
    )


@router.get("/dashboard/logout")
@router.post("/dashboard/logout")
def process_logout():
    """Đăng xuất phụ huynh và chuyển hướng về trang đăng nhập."""
    redirect = RedirectResponse(url="/dashboard/login?logout=1", status_code=status.HTTP_302_FOUND)
    redirect.delete_cookie(key="ogk_session")
    return redirect


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_overview(
    request: Request,
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    if not parent:
        return RedirectResponse(url="/dashboard/login", status_code=status.HTTP_302_FOUND)

    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)

    new_code = request.query_params.get("new_code")
    new_child_name = request.query_params.get("child_name")

    # Lấy danh sách các mã ghép đôi còn hiệu lực của phụ huynh này
    active_codes = (
        db.query(models.EnrollmentCode)
        .filter(
            models.EnrollmentCode.parent_id == parent.id,
            models.EnrollmentCode.used_at.is_(None),
            models.EnrollmentCode.expires_at > now,
        )
        .order_by(models.EnrollmentCode.created_at.desc())
        .all()
    )
    active_codes_data = []
    for ac in active_codes:
        ch = db.get(models.Child, ac.child_id)
        rem_sec = max(0, int((ac.expires_at - now).total_seconds()))
        active_codes_data.append(
            {
                "code": ac.code,
                "child_name": ch.display_name if ch else "Bé",
                "expires_in_minutes": max(1, (rem_sec + 59) // 60),
                "rem_sec": rem_sec,
                "created_at": ac.created_at.strftime("%H:%M:%S"),
            }
        )

    new_code_rem_sec = 600
    if new_code:
        nc_obj = db.get(models.EnrollmentCode, new_code.strip().upper())
        if nc_obj and nc_obj.parent_id == parent.id:
            new_code_rem_sec = max(0, int((nc_obj.expires_at - now).total_seconds()))

    devices = db.query(models.Device).order_by(models.Device.enrolled_at.desc()).all()
    children_data = []

    for d in devices:
        child = db.get(models.Child, d.child_id)
        child_name = child.display_name if child else "Bé"
        latest_policy = (
            db.query(models.Policy)
            .filter(models.Policy.child_id == d.child_id)
            .order_by(models.Policy.version.desc())
            .first()
        )
        quota_data = json.loads(latest_policy.quota_json) if latest_policy else {"daily_minutes": 120}
        daily_quota = quota_data.get("daily_minutes", 120)

        # Tính thời gian sử dụng hôm nay từ EventLog
        used_seconds = 0
        events_today = (
            db.query(models.EventLog)
            .filter(
                models.EventLog.device_id == d.id,
                models.EventLog.event_type == "screen_time",
                models.EventLog.created_at >= today_start,
            )
            .all()
        )
        for ev in events_today:
            used_seconds += ev.duration_sec

        used_minutes = round(used_seconds / 60, 1)
        percent = min(100, round((used_minutes / max(daily_quota, 1)) * 100)) if daily_quota > 0 else 0
        is_ws_active = bool(manager.active_connections.get(d.id))
        is_online = is_ws_active or ((now - d.last_seen_at) <= timedelta(seconds=ONLINE_THRESHOLD_SECONDS))

        children_data.append(
            {
                "name": child_name,
                "child_id": d.child_id,
                "device_id": d.id,
                "is_online": is_online,
                "last_seen_label": d.last_seen_at.strftime("%H:%M:%S %d/%m"),
                "policy_version": latest_policy.version if latest_policy else 1,
                "used_minutes": used_minutes,
                "daily_quota": daily_quota,
                "percent_used": percent,
            }
        )

    # Yêu cầu đang chờ duyệt (Pending Requests)
    pending_reqs = (
        db.query(models.ChildRequest)
        .filter(models.ChildRequest.status == "pending")
        .order_by(models.ChildRequest.created_at.desc())
        .all()
    )
    return templates.TemplateResponse(
        request=request,
        name="overview.html",
        context={
            "active_page": "overview",
            "current_user": parent,
            "children_data": children_data,
            "pending_requests": pending_reqs,
            "new_code": new_code,
            "new_child_name": new_child_name,
            "new_code_rem_sec": new_code_rem_sec,
            "active_codes": active_codes_data,
        },
    )


@router.post("/dashboard/action/create-code")
def create_enrollment_code_action(
    request: Request,
    child_name: str = Form(default="Minh An"),
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    """Tạo mã ghép đôi 8 ký tự cho trẻ từ Dashboard phụ huynh (Nghị định 13/2023)."""
    if not parent:
        return RedirectResponse(url="/dashboard/login", status_code=status.HTTP_302_FOUND)

    name_clean = child_name.strip() or "Bé yêu"
    child = (
        db.query(models.Child)
        .filter(models.Child.parent_id == parent.id, models.Child.display_name == name_clean)
        .first()
    )
    if not child:
        child = models.Child(parent_id=parent.id, display_name=name_clean)
        db.add(child)
        db.flush()

    code = security.generate_enrollment_code()
    expires_at = security.enrollment_code_expiry()
    enrollment = models.EnrollmentCode(
        code=code,
        parent_id=parent.id,
        child_id=child.id,
        expires_at=expires_at,
    )
    db.add(enrollment)

    now = datetime.utcnow()
    audit = models.AuditLog(
        actor_type="parent",
        actor_id=parent.id,
        action="create_enrollment_code",
        detail_json=json.dumps({"code": code, "child_id": child.id, "child_name": child.display_name}),
        created_at=now,
    )
    db.add(audit)
    db.commit()

    return RedirectResponse(
        url=f"/dashboard?new_code={code}&child_name={child.display_name}",
        status_code=status.HTTP_302_FOUND,
    )


@router.get("/dashboard/enroll", response_class=HTMLResponse)
def enroll_tab_page(
    request: Request,
    code: str | None = None,
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    """Tab riêng để lấy mã ghép đôi mới cho trẻ (lấy cho máy bất kỳ, không phân biệt ai)."""
    if not parent:
        return RedirectResponse(url="/dashboard/login", status_code=status.HTTP_302_FOUND)

    now = datetime.utcnow()
    raw_codes = (
        db.query(models.EnrollmentCode)
        .filter(models.EnrollmentCode.parent_id == parent.id)
        .order_by(models.EnrollmentCode.created_at.desc())
        .limit(20)
        .all()
    )

    codes_data = []
    latest_active_code = None

    for c in raw_codes:
        ch = db.get(models.Child, c.child_id)
        child_name = ch.display_name if ch else "Bé yêu"
        is_used = c.used_at is not None
        is_expired = c.expires_at < now
        rem_sec = max(0, int((c.expires_at - now).total_seconds()))
        rem_min = max(1, (rem_sec + 59) // 60) if not is_used and not is_expired else 0

        status_text = "Đã kết nối" if is_used else ("Đã hết hạn" if is_expired else "Đang chờ nhập")
        badge_class = "badge-success" if is_used else ("badge-danger" if is_expired else "badge-warning")

        item = {
            "code": c.code,
            "child_name": child_name,
            "created_at": c.created_at.strftime("%H:%M:%S %d/%m/%Y"),
            "expires_at": c.expires_at.strftime("%H:%M:%S %d/%m/%Y"),
            "expires_at_iso": c.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "rem_sec": rem_sec if not is_used and not is_expired else 0,
            "used_at": c.used_at.strftime("%H:%M:%S %d/%m/%Y") if c.used_at else None,
            "is_used": is_used,
            "is_expired": is_expired,
            "status_text": status_text,
            "badge_class": badge_class,
            "rem_min": rem_min,
        }
        codes_data.append(item)

        # Ưu tiên lấy mã truyền từ query param, nếu không thì lấy mã active gần nhất
        if code and c.code == code and not is_used and not is_expired:
            latest_active_code = item
        elif not latest_active_code and not is_used and not is_expired:
            latest_active_code = item

    return templates.TemplateResponse(
        request=request,
        name="enroll.html",
        context={
            "active_page": "enroll",
            "current_user": parent,
            "latest_code": latest_active_code,
            "codes_history": codes_data,
        },
    )


@router.get("/dashboard/enroll/status")
def get_enrollment_code_status(
    code: str,
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    """API endpoint để frontend kiểm tra realtime trạng thái mã ghép đôi mà không cần reload trang."""
    if not parent:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")

    code_clean = code.strip().upper()
    c = db.get(models.EnrollmentCode, code_clean)
    if not c or c.parent_id != parent.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="code_not_found")

    ch = db.get(models.Child, c.child_id)
    child_name = ch.display_name if ch else "Bé yêu"

    now = datetime.utcnow()
    is_used = c.used_at is not None
    is_expired = c.expires_at < now
    rem_sec = max(0, int((c.expires_at - now).total_seconds()))
    rem_min = max(1, (rem_sec + 59) // 60) if not is_used and not is_expired else 0

    status_text = "Đã kết nối" if is_used else ("Đã hết hạn" if is_expired else "Đang chờ nhập")
    badge_class = "badge-success" if is_used else ("badge-danger" if is_expired else "badge-warning")

    return {
        "code": c.code,
        "child_name": child_name,
        "is_used": is_used,
        "is_expired": is_expired,
        "rem_sec": rem_sec if not is_used and not is_expired else 0,
        "rem_min": rem_min,
        "status_text": status_text,
        "badge_class": badge_class,
        "used_at": c.used_at.strftime("%H:%M:%S %d/%m/%Y") if c.used_at else None,
        "expires_at": c.expires_at.strftime("%H:%M:%S %d/%m/%Y"),
    }


@router.post("/dashboard/enroll/generate")
def generate_enrollment_code_quick(
    child_name: str = Form(default="Minh An"),
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    """Sinh mã ghép đôi cho trẻ với tên do phụ huynh nhập."""
    if not parent:
        return RedirectResponse(url="/dashboard/login", status_code=status.HTTP_302_FOUND)

    name_clean = child_name.strip() if child_name and child_name.strip() else "Minh An"
    child = (
        db.query(models.Child)
        .filter(models.Child.parent_id == parent.id, models.Child.display_name == name_clean)
        .first()
    )
    if not child:
        child = models.Child(parent_id=parent.id, display_name=name_clean)
        db.add(child)
        db.flush()

    code = security.generate_enrollment_code()
    expires_at = security.enrollment_code_expiry()
    enrollment = models.EnrollmentCode(
        code=code,
        parent_id=parent.id,
        child_id=child.id,
        expires_at=expires_at,
    )
    db.add(enrollment)

    now = datetime.utcnow()
    audit = models.AuditLog(
        actor_type="parent",
        actor_id=parent.id,
        action="quick_generate_enrollment_code",
        detail_json=json.dumps({"code": code, "child_id": child.id, "child_name": child.display_name}),
        created_at=now,
    )
    db.add(audit)
    db.commit()

    return RedirectResponse(url=f"/dashboard/enroll?code={code}", status_code=status.HTTP_302_FOUND)


@router.post("/dashboard/action/command")
async def execute_dashboard_command(
    device_id: str = Form(...),
    command_type: str = Form(...),
    minutes: int = Form(default=15),
    db: Session = Depends(get_db),
):
    """Xử lý nút bấm phát lệnh khẩn cấp (Khóa máy, Mở khóa, Cộng giờ) từ Dashboard."""
    device = db.get(models.Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="device_not_found")

    payload = {"minutes": minutes} if command_type == "grant_minutes" else {}
    now = datetime.utcnow()
    cmd = models.Command(
        device_id=device.id,
        command_type=command_type,
        payload_json=json.dumps(payload),
        created_at=now,
    )
    db.add(cmd)
    db.flush()

    # Thử đẩy ngay qua WebSocket (<5s độ trễ)
    sent = await manager.send_command(
        device.id,
        {"command_id": cmd.id, "type": command_type, "payload": payload},
    )
    if sent:
        cmd.delivered_at = now

    db.commit()
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)


@router.post("/dashboard/action/request")
async def execute_dashboard_request(
    request_id: str = Form(...),
    action: str = Form(...),
    db: Session = Depends(get_db),
):
    """Phụ huynh bấm Duyệt hoặc Từ chối yêu cầu từ Dashboard."""
    req = db.get(models.ChildRequest, request_id)
    if req and req.status == "pending":
        now = datetime.utcnow()
        if action == "approve":
            req.status = "approved"
            if req.request_type == "grant_time":
                try:
                    mins = int(req.subject) if req.subject and req.subject.isdigit() else 15
                except Exception:
                    mins = 15
                cmd = models.Command(
                    device_id=req.device_id,
                    command_type="grant_minutes",
                    payload_json=json.dumps({"minutes": mins}),
                    created_at=now,
                )
                db.add(cmd)
                db.flush()
                sent = await manager.send_command(
                    req.device_id,
                    {"command_id": cmd.id, "type": "grant_minutes", "payload": {"minutes": mins}},
                )
                if sent:
                    cmd.delivered_at = now
        else:
            req.status = "rejected"
        req.resolved_at = now
        db.commit()

    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)


@router.get("/dashboard/policy", response_class=HTMLResponse)
# Chỉnh lại để hiển thị version của policy hiện có
def policy_page(
    request: Request,
    child_id: str | None = None,
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    if not parent:
        return RedirectResponse(url="/dashboard/login", status_code=status.HTTP_302_FOUND)

    children = db.query(models.Child).all()
    if not children:
        # Tạo trẻ demo nếu chưa có
        child = models.Child(parent_id=parent.id, display_name="Bé An")
        db.add(child)
        db.commit()
        db.refresh(child)
        children = [child]

    selected_child = None
    if child_id:
        selected_child = db.get(models.Child, child_id)
    if not selected_child:
        selected_child = children[0]

    latest_policy = (
        db.query(models.Policy)
        .filter(models.Policy.child_id == selected_child.id)
        .order_by(models.Policy.version.desc())
        .first()
    )

    quota = json.loads(latest_policy.quota_json) if latest_policy else {"daily_minutes": 120}
    schedule = json.loads(latest_policy.schedule_json) if latest_policy else {"start_time": "07:00", "end_time": "21:30"}
    if "matrix" not in schedule or not security.validate_or_normalize_matrix(schedule["matrix"]):
        schedule["matrix"] = security.generate_matrix_from_times(
            schedule.get("start_time", "00:00"), schedule.get("end_time", "23:30")
        )
    app_rules = json.loads(latest_policy.app_rules_json) if latest_policy else {"mode": "blacklist", "blacklist": []}
    if isinstance(app_rules, list):
        app_rules = {"mode": "blacklist", "blacklist": app_rules, "whitelist": []}
    app_mode = app_rules.get("mode", "blacklist")
    if app_mode == "whitelist":
        raw_apps = app_rules.get("whitelist", [])
    else:
        raw_apps = app_rules.get("blacklist", [])

    lines = []
    for item in raw_apps:
        if isinstance(item, dict):
            n = item.get("name", "")
            h = item.get("sha256", "")
            if n and h:
                lines.append(f"{n}:{h}")
            elif n:
                lines.append(n)
            elif h:
                lines.append(h)
        else:
            lines.append(str(item))
    blocked_apps_text = "\n".join(lines)

    domain_rules = json.loads(latest_policy.domain_rules_json) if latest_policy else {"blacklist": []}
    blocked_domains_list = domain_rules.get("blacklist", []) if isinstance(domain_rules, dict) else (domain_rules if isinstance(domain_rules, list) else [])

    return templates.TemplateResponse(
        request=request,
        name="policy.html",
        context={
            "active_page": "policy",
            "current_user": parent,
            "children": children,
            "selected_child": selected_child,
            "current_policy": latest_policy,
            "quota": quota,
            "schedule": schedule,
            "schedule_matrix_json": json.dumps(schedule["matrix"]),
            "app_mode": app_mode,
            "blocked_apps_text": blocked_apps_text,
            "blocked_domains_text": "\n".join(blocked_domains_list),
            "success_msg": None,
        },
    )


@router.post("/dashboard/policy/save", response_class=HTMLResponse)
def save_policy_page(
    request: Request,
    child_id: str = Form(...),
    daily_minutes: int = Form(...),
    start_time: str = Form("07:00"),
    end_time: str = Form("21:30"),
    schedule_matrix: str = Form(""),
    app_mode: str = Form("blacklist"),
    blocked_apps: str = Form(""),
    blocked_domains: str = Form(""),
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    if not parent:
        return RedirectResponse(url="/dashboard/login", status_code=status.HTTP_302_FOUND)

    child = db.get(models.Child, child_id)
    if not child:
        raise HTTPException(status_code=404, detail="child_not_found")

    app_mode_clean = app_mode.strip().lower() if app_mode else "blacklist"
    if app_mode_clean not in ("blacklist", "whitelist"):
        app_mode_clean = "blacklist"

    app_list = []
    for line in blocked_apps.splitlines():
        line_clean = line.strip()
        if not line_clean:
            continue
        parsed = security.parse_app_rule_entry(line_clean)
        if parsed.get("name") and parsed.get("sha256"):
            app_list.append(f"{parsed['name']}:{parsed['sha256']}")
        elif parsed.get("name"):
            app_list.append(parsed["name"])
        elif parsed.get("sha256"):
            app_list.append(parsed["sha256"])
        else:
            app_list.append(line_clean.lower())

    domain_list = []
    for line in blocked_domains.splitlines():
        d = line.strip().lower()
        if not d:
            continue
        if d.startswith("http://"):
            d = d[7:]
        elif d.startswith("https://"):
            d = d[8:]
        d = d.split("/")[0].split(":")[0].strip()
        if d and d not in domain_list:
            domain_list.append(d)

    # Xử lý ma trận lịch tuần 7x48
    matrix = None
    if schedule_matrix.strip():
        try:
            parsed = json.loads(schedule_matrix)
            matrix = security.validate_or_normalize_matrix(parsed)
        except Exception:
            matrix = None

    if matrix is None:
        matrix = security.generate_matrix_from_times(start_time, end_time)

    schedule_data = {
        "start_time": start_time,
        "end_time": end_time,
        "matrix": matrix,
    }

    latest = (
        db.query(models.Policy)
        .filter(models.Policy.child_id == child_id)
        .order_by(models.Policy.version.desc())
        .first()
    )
    new_version = (latest.version + 1) if latest else 1
    now = datetime.utcnow()

    if app_mode_clean == "whitelist":
        app_rules_data = {"mode": "whitelist", "whitelist": app_list, "blacklist": []}
    else:
        app_rules_data = {"mode": "blacklist", "blacklist": app_list, "whitelist": []}

    new_policy = models.Policy(
        child_id=child_id,
        version=new_version,
        quota_json=json.dumps({"daily_minutes": daily_minutes}),
        schedule_json=json.dumps(schedule_data),
        app_rules_json=json.dumps(app_rules_data),
        domain_rules_json=json.dumps({"mode": "blacklist", "blacklist": domain_list}),
        created_at=now,
    )
    db.add(new_policy)

    # Ghi AuditLog
    audit = models.AuditLog(
        actor_type="parent",
        actor_id=parent.id,
        action="policy_updated",
        detail_json=json.dumps({
            "child_id": child_id,
            "version": new_version,
            "daily_minutes": daily_minutes,
            "app_mode": app_mode_clean,
            "app_count": len(app_list),
        }),
        created_at=now,
    )
    db.add(audit)
    db.commit()

    children = db.query(models.Child).all()
    return templates.TemplateResponse(
        request,
        "policy.html",
        {
            "active_page": "policy",
            "current_user": parent,
            "children": children,
            "selected_child": child,
            "current_policy": new_policy,
            "quota": {"daily_minutes": daily_minutes},
            "schedule": schedule_data,
            "schedule_matrix_json": json.dumps(matrix),
            "app_mode": app_mode_clean,
            "blocked_apps_text": "\n".join(app_list),
            "blocked_domains_text": "\n".join(domain_list),
            "success_msg": f"Đã lưu chính sách phiên bản v{new_version} thành công! Máy trẻ em sẽ tự cập nhật khi nhịp tim hoặc nhận lệnh.",
        },
    )


@router.get("/dashboard/requests", response_class=HTMLResponse)
def requests_page(
    request: Request,
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    if not parent:
        return RedirectResponse(url="/dashboard/login", status_code=status.HTTP_302_FOUND)

    reqs = db.query(models.ChildRequest).order_by(models.ChildRequest.created_at.desc()).all()
    rows = []
    for r in reqs:
        rows.append(
            {
                "id": r.id,
                "request_type": r.request_type,
                "subject": r.subject or "—",
                "reason": r.reason,
                "status": r.status,
                "created_at": r.created_at.strftime("%H:%M:%S %d/%m/%Y"),
                "resolved_at": r.resolved_at.strftime("%H:%M:%S %d/%m/%Y") if r.resolved_at else None,
            }
        )

    return templates.TemplateResponse(
        request,
        "requests.html",
        {
            "active_page": "requests",
            "current_user": parent,
            "requests": rows,
        },
    )


@router.get("/dashboard/reports", response_class=HTMLResponse)
def reports_page(
    request: Request,
    child_id: str | None = None,
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    if not parent:
        return RedirectResponse(url="/dashboard/login", status_code=status.HTTP_302_FOUND)

    children = db.query(models.Child).filter(models.Child.parent_id == parent.id).all()
    if not children:
        children = db.query(models.Child).all()

    selected_child = None
    if child_id:
        selected_child = db.get(models.Child, child_id)
    if not selected_child and children:
        selected_child = children[0]

    if selected_child:
        stats = get_child_stats_summary(selected_child.id, db)
    else:
        stats = {
            "today_screen_time_minutes": 0,
            "daily_quota": 120,
            "remaining_minutes": 120,
            "percent_used": 0,
            "hourly_list": [],
            "daily_list": [],
            "top_blocked_apps": [],
            "top_blocked_webs": [],
            "recent_events": [],
            "time_blocks": {"morning_minutes": 0, "afternoon_minutes": 0, "evening_minutes": 0, "night_minutes": 0},
        }

    purged = request.query_params.get("purged")
    cleaned = request.query_params.get("cleaned")

    return templates.TemplateResponse(
        request,
        "reports.html",
        {
            "active_page": "reports",
            "current_user": parent,
            "children": children,
            "selected_child": selected_child,
            "stats": stats,
            "purged": purged,
            "cleaned": cleaned,
            "retention_days": 90,
        },
    )


@router.post("/dashboard/action/purge-child-data")
async def purge_child_data_action(
    request: Request,
    child_id: str = Form(...),
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    """Xóa toàn bộ dữ liệu của con tôi (Server + Agent cache) theo Nghị định 13/2023."""
    if not parent:
        return RedirectResponse(url="/dashboard/login", status_code=status.HTTP_302_FOUND)

    child = db.get(models.Child, child_id)
    if not child:
        raise HTTPException(status_code=404, detail="child_not_found")

    # 1. Xóa EventLog & ChildRequest của trẻ trên Server
    deleted_events = (
        db.query(models.EventLog)
        .filter(models.EventLog.child_id == child_id)
        .delete(synchronize_session=False)
    )
    deleted_requests = (
        db.query(models.ChildRequest)
        .filter(models.ChildRequest.child_id == child_id)
        .delete(synchronize_session=False)
    )

    # 2. Phát lệnh khẩn cấp clear_data tới tất cả thiết bị của trẻ
    devices = db.query(models.Device).filter(models.Device.child_id == child_id).all()
    now = datetime.utcnow()
    for d in devices:
        cmd = models.Command(
            device_id=d.id,
            command_type="clear_data",
            payload_json=json.dumps({"child_id": child_id, "action": "purge_child_data"}),
            created_at=now,
        )
        db.add(cmd)
        db.flush()
        sent = await manager.send_command(
            d.id,
            {"command_id": cmd.id, "type": "clear_data", "payload": {"child_id": child_id}},
        )
        if sent:
            cmd.delivered_at = now

    # 3. Ghi AuditLog
    audit = models.AuditLog(
        actor_type="parent",
        actor_id=parent.id,
        action="purge_child_data",
        detail_json=json.dumps({
            "child_id": child_id,
            "child_name": child.display_name,
            "deleted_events": deleted_events,
            "deleted_requests": deleted_requests,
            "devices_count": len(devices),
        }),
        created_at=now,
    )
    db.add(audit)
    db.commit()

    return RedirectResponse(
        url=f"/dashboard/reports?child_id={child_id}&purged=1",
        status_code=status.HTTP_302_FOUND,
    )


@router.post("/dashboard/action/cleanup-logs")
def cleanup_logs_action(
    request: Request,
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    """Kích hoạt dọn dẹp các bản ghi quá 90 ngày."""
    if not parent:
        return RedirectResponse(url="/dashboard/login", status_code=status.HTTP_302_FOUND)

    res = cleanup_old_logs(db, days=90)
    now = datetime.utcnow()
    audit = models.AuditLog(
        actor_type="parent",
        actor_id=parent.id,
        action="manual_retention_cleanup",
        detail_json=json.dumps(res),
        created_at=now,
    )
    db.add(audit)
    db.commit()

    return RedirectResponse(
        url="/dashboard/reports?cleaned=1",
        status_code=status.HTTP_302_FOUND,
    )


@router.get("/dashboard/today", response_class=HTMLResponse)
@router.get("/dashboard/child/{child_id}/today", response_class=HTMLResponse)
@router.get("/today", response_class=HTMLResponse)
def child_today_screen(
    request: Request,
    child_id: str | None = None,
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    """Màn hình 'Hôm nay em đã dùng gì' cho trẻ — ngôn ngữ đơn giản, hình ảnh minh họa sinh động."""
    selected_child = None
    if child_id:
        selected_child = db.get(models.Child, child_id)

    if not selected_child and parent:
        selected_child = db.query(models.Child).filter(models.Child.parent_id == parent.id).first()

    if not selected_child:
        selected_child = db.query(models.Child).first()

    if not selected_child:
        raise HTTPException(status_code=404, detail="child_not_found")

    stats = get_child_stats_summary(selected_child.id, db)

    # Đưa ra thông điệp thân thiện theo thời lượng đã dùng
    quota_min = stats["daily_quota"]
    rem_min = stats["remaining_minutes"]

    if rem_min <= 0:
        kid_mood = "completed"
        kid_message = "Em đã dùng hết thời gian hôm nay rồi! Hãy nghỉ ngơi, uống nước và vận động nhé! ⚽📚"
        kid_badge = "🏆 Bé xuất sắc hoàn thành mục tiêu ngày!"
    elif rem_min <= 15:
        kid_mood = "warning"
        kid_message = f"Sắp hết giờ rồi em nhé! Em còn khoảng {int(rem_min)} phút, hãy chuẩn bị lưu bài tập nhé! 💾⏰"
        kid_badge = "⭐ Bé chăm chỉ & giữ gìn đôi mắt!"
    else:
        kid_mood = "good"
        kid_message = f"Em vẫn còn {int(rem_min)} phút vui học hôm nay! Nhớ ngồi thẳng lưng và cách màn hình 50cm nhé! 👀✨"
        kid_badge = "🚀 Nhà thám hiểm công nghệ ngoan ngoãn!"

    requested = request.query_params.get("requested")

    return templates.TemplateResponse(
        request,
        "child_today.html",
        {
            "child": selected_child,
            "stats": stats,
            "kid_mood": kid_mood,
            "kid_message": kid_message,
            "kid_badge": kid_badge,
            "requested": requested,
            "is_parent_logged_in": parent is not None,
            "current_user": parent,
            "active_page": "today",
        },
    )


@router.post("/today/request-time")
def child_request_time_action(
    request: Request,
    child_id: str = Form(...),
    minutes: int = Form(15),
    reason: str = Form("Con cần thêm thời gian để hoàn thành bài tập"),
    db: Session = Depends(get_db),
):
    """Trẻ gửi yêu cầu xin thêm giờ từ màn hình 'Hôm nay em đã dùng gì'."""
    child = db.get(models.Child, child_id)
    if not child:
        raise HTTPException(status_code=404, detail="child_not_found")

    device = db.query(models.Device).filter(models.Device.child_id == child_id).first()
    device_id = device.id if device else "web_portal"
    now = datetime.utcnow()
    req = models.ChildRequest(
        child_id=child.id,
        device_id=device_id,
        request_type="grant_time",
        subject=str(minutes),
        reason=reason.strip() or "Bé xin thêm thời gian từ màn hình Hôm nay em đã dùng gì",
        status="pending",
        created_at=now,
    )
    db.add(req)
    db.commit()

    return RedirectResponse(
        url=f"/dashboard/today?child_id={child_id}&requested=1",
        status_code=status.HTTP_302_FOUND,
    )



@router.get("/dashboard/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    if not parent:
        return RedirectResponse(url="/dashboard/login", status_code=status.HTTP_302_FOUND)

    logs = db.query(models.AuditLog).order_by(models.AuditLog.created_at.desc()).limit(100).all()
    rows = []
    for l in logs:
        rows.append(
            {
                "created_at": l.created_at.strftime("%H:%M:%S %d/%m/%Y"),
                "actor_type": l.actor_type,
                "action": l.action,
                "detail_json": l.detail_json,
            }
        )

    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "active_page": "audit",
            "current_user": parent,
            "logs": rows,
        },
    )


@router.get("/dashboard/devices")
def device_status_page(
    request: Request,
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    """Trang xem danh sách thiết bị."""
    if not parent:
        return RedirectResponse(url="/dashboard/login", status_code=status.HTTP_302_FOUND)
    now = datetime.utcnow()
    devices = db.query(models.Device).order_by(models.Device.enrolled_at.desc()).all()

    rows = []
    for device in devices:
        child = db.get(models.Child, device.child_id)
        latest_policy = (
            db.query(models.Policy)
            .filter(models.Policy.child_id == device.child_id)
            .order_by(models.Policy.version.desc())
            .first()
        )
        pending_count = (
            db.query(models.Command)
            .filter(models.Command.device_id == device.id, models.Command.delivered_at.is_(None))
            .count()
        )
        is_ws_active = bool(manager.active_connections.get(device.id))
        is_online = is_ws_active or ((now - device.last_seen_at) <= timedelta(seconds=ONLINE_THRESHOLD_SECONDS))

        rows.append(
            {
                "device_id": device.id,
                "child_name": child.display_name if child else "(không rõ)",
                "is_online": is_online,
                "last_seen_label": device.last_seen_at.strftime("%H:%M:%S %d/%m/%Y"),
                "policy_version": latest_policy.version if latest_policy else "—",
                "pending_count": pending_count,
                "status": device.status,
            }
        )

    return templates.TemplateResponse(
        request,
        "device_status.html",
        {
            "devices": rows, 
            "generated_at": now.strftime("%H:%M:%S %d/%m/%Y")
        },
    )
