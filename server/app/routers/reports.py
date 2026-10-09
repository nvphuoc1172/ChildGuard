"""Báo cáo & Thống kê (Reports) — xem mục 6 trong Design.md.

GET /reports/{child_id}: Báo cáo tổng hợp thời gian sử dụng, app và domain đã chặn.
"""
from collections import Counter
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models
from app.database import get_db

router = APIRouter(tags=["reports"])


@router.get("/reports/{child_id}")
def get_child_reports(child_id: str, db: Session = Depends(get_db)):
    """Tổng hợp dữ liệu sử dụng máy của trẻ từ EventLog."""
    child = db.get(models.Child, child_id)
    if child is None:
        raise HTTPException(status_code=404, detail="child_not_found")

    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)
    week_start = today_start - timedelta(days=6)

    # Lấy các sự kiện trong 7 ngày
    events = (
        db.query(models.EventLog)
        .filter(models.EventLog.child_id == child_id, models.EventLog.created_at >= week_start)
        .order_by(models.EventLog.created_at.desc())
        .all()
    )

    today_screen_time_sec = 0
    blocked_apps_counter = Counter()
    blocked_webs_counter = Counter()
    daily_usage = { (today_start - timedelta(days=i)).strftime("%d/%m"): 0 for i in range(6, -1, -1) }

    recent_events = []

    for ev in events:
        day_str = ev.created_at.strftime("%d/%m")
        if ev.event_type == "screen_time":
            if day_str in daily_usage:
                daily_usage[day_str] += ev.duration_sec
            if ev.created_at >= today_start:
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

    # Chuyển đổi daily_usage sang phút
    daily_minutes = {k: round(v / 60, 1) for k, v in daily_usage.items()}

    return {
        "child_id": child.id,
        "child_name": child.display_name,
        "today_screen_time_minutes": round(today_screen_time_sec / 60, 1),
        "daily_minutes": daily_minutes,
        "top_blocked_apps": [
            {"name": name, "count": count} for name, count in blocked_apps_counter.most_common(5)
        ],
        "top_blocked_webs": [
            {"name": name, "count": count} for name, count in blocked_webs_counter.most_common(5)
        ],
        "recent_events": recent_events,
    }
