"""Báo cáo & Thống kê (Reports) — xem mục 6 trong Design.md.

Hỗ trợ:
- GET /reports/{child_id}: Báo cáo tổng hợp thời gian sử dụng (ngày, tuần), top 10 app/domain bị chặn.
- POST /reports/cleanup: Tự động dọn dẹp nhật ký, sự kiện quá 90 ngày.
- POST /reports/{child_id}/purge: Xóa toàn bộ dữ liệu của con trên Server và phát lệnh xóa sạch bộ đệm Agent.
"""
from collections import Counter
from datetime import datetime, timedelta
import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models
from app.database import get_db

router = APIRouter(tags=["reports"])


def cleanup_old_logs(db: Session, days: int = 90) -> dict:
    """Tự động dọn dẹp log, sự kiện, thống kê, kiểm toán quá 90 ngày."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    deleted_events = (
        db.query(models.EventLog)
        .filter(models.EventLog.created_at < cutoff)
        .delete(synchronize_session=False)
    )
    deleted_audit = (
        db.query(models.AuditLog)
        .filter(models.AuditLog.created_at < cutoff)
        .delete(synchronize_session=False)
    )
    deleted_commands = (
        db.query(models.Command)
        .filter(models.Command.created_at < cutoff)
        .delete(synchronize_session=False)
    )
    deleted_requests = (
        db.query(models.ChildRequest)
        .filter(models.ChildRequest.created_at < cutoff)
        .delete(synchronize_session=False)
    )
    db.commit()
    return {
        "cutoff_date": cutoff.isoformat(),
        "retention_days": days,
        "deleted_events": deleted_events,
        "deleted_audit": deleted_audit,
        "deleted_commands": deleted_commands,
        "deleted_requests": deleted_requests,
    }


def get_child_stats_summary(child_id: str, db: Session) -> dict:
    """Tổng hợp dữ liệu sử dụng máy chi tiết của trẻ từ EventLog & Policy."""
    child = db.get(models.Child, child_id)
    if child is None:
        raise HTTPException(status_code=404, detail="child_not_found")

    # Lấy hạn mức quota từ Policy mới nhất của trẻ
    latest_policy = (
        db.query(models.Policy)
        .filter(models.Policy.child_id == child_id)
        .order_by(models.Policy.version.desc())
        .first()
    )
    daily_quota = 120
    if latest_policy:
        try:
            q_data = json.loads(latest_policy.quota_json)
            daily_quota = q_data.get("daily_minutes", 120)
        except Exception:
            daily_quota = 120

    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)
    week_start = today_start - timedelta(days=6)

    # Lấy tất cả sự kiện trong vòng 7 ngày gần nhất
    events = (
        db.query(models.EventLog)
        .filter(models.EventLog.child_id == child_id, models.EventLog.created_at >= week_start)
        .order_by(models.EventLog.created_at.desc())
        .all()
    )

    today_screen_time_sec = 0
    blocked_apps_counter = Counter()
    blocked_webs_counter = Counter()

    # Biểu đồ theo tuần: 7 ngày (dd/mm)
    days_keys = [(today_start - timedelta(days=i)).strftime("%d/%m") for i in range(6, -1, -1)]
    daily_usage = {k: 0 for k in days_keys}

    # Biểu đồ theo ngày: 24 mốc giờ hôm nay (00:00 -> 23:00)
    hourly_usage = {f"{h:02d}:00": 0 for h in range(24)}

    # Khung giờ buổi trong ngày cho trẻ (Sáng, Chiều, Tối, Đêm)
    morning_sec = 0     # 06:00 - 12:00
    afternoon_sec = 0   # 12:00 - 18:00
    evening_sec = 0     # 18:00 - 22:00
    night_sec = 0       # 22:00 - 06:00

    recent_events = []

    for ev in events:
        day_str = ev.created_at.strftime("%d/%m")
        if ev.event_type == "screen_time":
            if day_str in daily_usage:
                daily_usage[day_str] += ev.duration_sec
            if ev.created_at >= today_start:
                today_screen_time_sec += ev.duration_sec
                hour_key = ev.created_at.strftime("%H:00")
                if hour_key in hourly_usage:
                    hourly_usage[hour_key] += ev.duration_sec

                ev_hour = ev.created_at.hour
                if 6 <= ev_hour < 12:
                    morning_sec += ev.duration_sec
                elif 12 <= ev_hour < 18:
                    afternoon_sec += ev.duration_sec
                elif 18 <= ev_hour < 22:
                    evening_sec += ev.duration_sec
                else:
                    night_sec += ev.duration_sec

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

    # Chuyển đổi sang phút
    daily_minutes = {k: round(v / 60, 1) for k, v in daily_usage.items()}
    hourly_minutes = {k: round(v / 60, 1) for k, v in hourly_usage.items()}
    today_screen_time_minutes = round(today_screen_time_sec / 60, 1)
    remaining_minutes = max(0, round(daily_quota - today_screen_time_minutes, 1))

    # Top 10 ứng dụng và Top 10 tên miền bị chặn kèm số lần
    top_apps_raw = blocked_apps_counter.most_common(10)
    max_app_count = top_apps_raw[0][1] if top_apps_raw else 1
    top_blocked_apps = [
        {
            "rank": idx + 1,
            "name": name,
            "count": count,
            "percent": min(100, round((count / max_app_count) * 100)),
        }
        for idx, (name, count) in enumerate(top_apps_raw)
    ]

    top_webs_raw = blocked_webs_counter.most_common(10)
    max_web_count = top_webs_raw[0][1] if top_webs_raw else 1
    top_blocked_webs = [
        {
            "rank": idx + 1,
            "name": name,
            "count": count,
            "percent": min(100, round((count / max_web_count) * 100)),
        }
        for idx, (name, count) in enumerate(top_webs_raw)
    ]

    # Danh sách chuẩn hóa cho biểu đồ cột trên Dashboard
    max_hour_min = max(hourly_minutes.values()) if hourly_minutes and max(hourly_minutes.values()) > 0 else 60.0
    hourly_list = [
        {
            "hour": k,
            "hour_short": k.split(":")[0] + "h",
            "minutes": v,
            "percent": min(100, round((v / max_hour_min) * 100)) if max_hour_min > 0 else 0,
        }
        for k, v in hourly_minutes.items()
    ]

    max_day_min = max(daily_minutes.values()) if daily_minutes and max(daily_minutes.values()) > 0 else 120.0
    daily_list = [
        {
            "day": k,
            "minutes": v,
            "percent": min(100, round((v / max_day_min) * 100)) if max_day_min > 0 else 0,
        }
        for k, v in daily_minutes.items()
    ]

    return {
        "child_id": child.id,
        "child_name": child.display_name,
        "daily_quota": daily_quota,
        "today_screen_time_sec": today_screen_time_sec,
        "today_screen_time_minutes": today_screen_time_minutes,
        "remaining_minutes": remaining_minutes,
        "percent_used": min(100, round((today_screen_time_minutes / max(daily_quota, 1)) * 100)),
        "daily_minutes": daily_minutes,
        "weekly_minutes": daily_minutes,
        "hourly_minutes": hourly_minutes,
        "hourly_list": hourly_list,
        "daily_list": daily_list,
        "top_blocked_apps": top_blocked_apps,
        "top_blocked_webs": top_blocked_webs,
        "recent_events": recent_events,
        "time_blocks": {
            "morning_minutes": round(morning_sec / 60, 1),
            "afternoon_minutes": round(afternoon_sec / 60, 1),
            "evening_minutes": round(evening_sec / 60, 1),
            "night_minutes": round(night_sec / 60, 1),
        },
    }


@router.get("/reports/{child_id}")
def get_child_reports(child_id: str, db: Session = Depends(get_db)):
    """API tổng hợp dữ liệu sử dụng máy của trẻ từ EventLog."""
    return get_child_stats_summary(child_id, db)


@router.post("/reports/cleanup")
def trigger_log_cleanup(days: int = 90, db: Session = Depends(get_db)):
    """Tự động dọn dẹp các bản ghi log/sự kiện/kiểm toán quá 90 ngày."""
    return cleanup_old_logs(db, days=days)


@router.post("/reports/{child_id}/purge")
async def purge_child_data_api(child_id: str, db: Session = Depends(get_db)):
    """Xóa toàn bộ dữ liệu của con trên Server và phát lệnh xóa sạch bộ đệm của Agent."""
    child = db.get(models.Child, child_id)
    if not child:
        raise HTTPException(status_code=404, detail="child_not_found")

    # 1. Xóa EventLog & ChildRequest trên server
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
    from app.routers.commands import manager

    devices = db.query(models.Device).filter(models.Device.child_id == child_id).all()
    now = datetime.utcnow()
    notified_count = 0
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
            notified_count += 1

    # 3. Ghi AuditLog minh bạch theo Nghị định 13/2023
    audit = models.AuditLog(
        actor_type="system",
        actor_id=child.parent_id,
        action="purge_child_data",
        detail_json=json.dumps({
            "child_id": child_id,
            "deleted_events": deleted_events,
            "deleted_requests": deleted_requests,
            "devices_count": len(devices),
        }),
        created_at=now,
    )
    db.add(audit)
    db.commit()

    return {
        "status": "ok",
        "child_id": child_id,
        "deleted_events": deleted_events,
        "deleted_requests": deleted_requests,
        "devices_commanded": len(devices),
        "devices_instant_notified": notified_count,
    }
