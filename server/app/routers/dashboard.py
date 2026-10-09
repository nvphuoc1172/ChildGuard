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

router = APIRouter(tags=["dashboard"])

TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "dashboard" / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

ONLINE_THRESHOLD_SECONDS = 90


def _get_or_create_demo_parent(db: Session) -> models.Parent:
    parent = db.query(models.Parent).filter(models.Parent.email == "demo@ogk.local").first()
    if not parent:
        parent = models.Parent(
            email="demo@ogk.local",
            password_hash=security.hash_password("admin123"),
            full_name="Phụ huynh Demo",
        )
        db.add(parent)
        db.commit()
        db.refresh(parent)
    return parent


@router.get("/dashboard/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/dashboard/login", response_class=HTMLResponse)
def process_login(
    request: Request,
    response: Response,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    parent = (
        db.query(models.Parent)
        .filter(models.Parent.email == email.strip().lower())
        .first()
    )
    if not parent or not security.verify_password(password, parent.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Email hoặc mật khẩu không chính xác."},
            status_code=401,
        )

    token = security.create_parent_session(parent.id)
    redirect = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(
        key="ogk_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=86400,
    )
    return redirect


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_overview(
    request: Request,
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    if not parent:
        parent = _get_or_create_demo_parent(db)

    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)

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
        is_online = (now - d.last_seen_at) <= timedelta(seconds=ONLINE_THRESHOLD_SECONDS)

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
        },
    )


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
        parent = _get_or_create_demo_parent(db)

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
    app_rules = json.loads(latest_policy.app_rules_json) if latest_policy else {"blacklist": []}
    domain_rules = json.loads(latest_policy.domain_rules_json) if latest_policy else {"blacklist": []}

    blocked_apps_list = app_rules.get("blacklist", [])
    blocked_domains_list = domain_rules.get("blacklist", [])

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
            "blocked_apps_text": "\n".join(blocked_apps_list),
            "blocked_domains_text": "\n".join(blocked_domains_list),
            "success_msg": None,
        },
    )


@router.post("/dashboard/policy/save", response_class=HTMLResponse)
def save_policy_page(
    request: Request,
    child_id: str = Form(...),
    daily_minutes: int = Form(...),
    start_time: str = Form(...),
    end_time: str = Form(...),
    blocked_apps: str = Form(""),
    blocked_domains: str = Form(""),
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    if not parent:
        parent = _get_or_create_demo_parent(db)

    child = db.get(models.Child, child_id)
    if not child:
        raise HTTPException(status_code=404, detail="child_not_found")

    app_list = [line.strip().lower() for line in blocked_apps.splitlines() if line.strip()]
    domain_list = [line.strip().lower() for line in blocked_domains.splitlines() if line.strip()]

    latest = (
        db.query(models.Policy)
        .filter(models.Policy.child_id == child_id)
        .order_by(models.Policy.version.desc())
        .first()
    )
    new_version = (latest.version + 1) if latest else 1
    now = datetime.utcnow()

    new_policy = models.Policy(
        child_id=child_id,
        version=new_version,
        quota_json=json.dumps({"daily_minutes": daily_minutes}),
        schedule_json=json.dumps({"start_time": start_time, "end_time": end_time}),
        app_rules_json=json.dumps({"mode": "blacklist", "blacklist": app_list}),
        domain_rules_json=json.dumps({"mode": "blacklist", "blacklist": domain_list}),
        created_at=now,
    )
    db.add(new_policy)

    # Ghi AuditLog
    audit = models.AuditLog(
        actor_type="parent",
        actor_id=parent.id,
        action="policy_updated",
        detail_json=json.dumps({"child_id": child_id, "version": new_version, "daily_minutes": daily_minutes}),
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
            "schedule": {"start_time": start_time, "end_time": end_time},
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
        parent = _get_or_create_demo_parent(db)

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
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    if not parent:
        parent = _get_or_create_demo_parent(db)

    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)
    week_start = today_start - timedelta(days=6)

    events = (
        db.query(models.EventLog)
        .filter(models.EventLog.created_at >= week_start)
        .order_by(models.EventLog.created_at.desc())
        .all()
    )

    today_screen_time_sec = 0
    blocked_apps_counter = Counter()
    blocked_webs_counter = Counter()
    recent_events = []

    for ev in events:
        if ev.event_type == "screen_time" and ev.created_at >= today_start:
            today_screen_time_sec += ev.duration_sec
        elif ev.event_type == "app_blocked" and ev.subject:
            blocked_apps_counter[ev.subject] += 1
        elif ev.event_type == "web_blocked" and ev.subject:
            blocked_webs_counter[ev.subject] += 1

        if len(recent_events) < 20:
            recent_events.append(
                {
                    "type": ev.event_type,
                    "subject": ev.subject or "—",
                    "duration_sec": ev.duration_sec,
                    "time": ev.created_at.strftime("%H:%M:%S %d/%m"),
                }
            )

    stats = {
        "today_screen_time_minutes": round(today_screen_time_sec / 60, 1),
        "top_blocked_apps": [{"name": k, "count": v} for k, v in blocked_apps_counter.most_common(5)],
        "top_blocked_webs": [{"name": k, "count": v} for k, v in blocked_webs_counter.most_common(5)],
        "recent_events": recent_events,
    }

    return templates.TemplateResponse(
        request,
        "reports.html",
        {
            "active_page": "reports",
            "current_user": parent,
            "stats": stats,
        },
    )


@router.get("/dashboard/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    db: Session = Depends(get_db),
    parent: models.Parent | None = Depends(get_optional_parent),
):
    if not parent:
        parent = _get_or_create_demo_parent(db)

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
def device_status_page(request: Request, db: Session = Depends(get_db)):
    """Trang tương thích ngược xem danh sách thiết bị."""
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
        is_online = (now - device.last_seen_at) <= timedelta(seconds=ONLINE_THRESHOLD_SECONDS)

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
