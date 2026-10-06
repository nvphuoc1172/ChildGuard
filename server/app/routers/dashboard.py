"""GET /dashboard/devices — giao diện thật đầu tiên, dùng dữ liệu thật
từ DB thay vì mock. CHƯA có xác thực phụ huynh (auth.py làm ở tính năng
sau) nên đây là trang xem CHUNG mọi thiết bị — chỉ dùng để tự kiểm tra
heartbeat trong lúc phát triển, không phải giao diện cuối cùng cho
phụ huynh (xem dashboard/templates/overview.html cho bản đầy đủ,
hiện vẫn đang chờ nối auth + quota thật).
"""
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app import models
from app.database import get_db

router = APIRouter(tags=["dashboard"])

TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "dashboard" / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Heartbeat gửi mỗi 60s — cho dư 30s để bù độ trễ mạng trước khi coi là mất kết nối.
ONLINE_THRESHOLD_SECONDS = 90


@router.get("/dashboard/devices")
def device_status_page(request: Request, db: Session = Depends(get_db)):
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
        "device_status.html",
        {"request": request, "devices": rows, "generated_at": now.strftime("%H:%M:%S %d/%m/%Y")},
    )
