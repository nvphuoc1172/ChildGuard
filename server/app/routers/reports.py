"""Báo cáo & Thống kê (Reports) — xem mục 6 trong Design.md.

Hỗ trợ:
- GET /reports/{child_id}: Báo cáo tổng hợp thời gian sử dụng (ngày, tuần), top 10 app/domain bị chặn.
- POST /reports/cleanup: Tự động dọn dẹp nhật ký, sự kiện quá 90 ngày.
- POST /reports/{child_id}/purge: Xóa toàn bộ dữ liệu của con trên Server và phát lệnh xóa sạch bộ đệm Agent.
"""
import io
import json
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.domain_categories import CATEGORY_DEFINITIONS, classify_domain
from app.event_contract import normalize_app_subject, normalize_domain_subject

router = APIRouter(tags=["reports"])
REPORT_TIMEZONE = ZoneInfo("Asia/Ho_Chi_Minh")
DOMAIN_ACTIVITY_BUCKET_SECONDS = 60


def utc_naive_to_report_time(value: datetime) -> datetime:
    """Convert the database's naive-UTC timestamps to GMT+7 for reports."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(REPORT_TIMEZONE)


def _local_period_bounds() -> tuple[datetime, datetime, datetime]:
    """Return local now plus UTC-naive starts for today and the 7-day window."""
    local_now = datetime.now(REPORT_TIMEZONE)
    local_today = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    local_week = local_today - timedelta(days=6)
    today_utc = local_today.astimezone(timezone.utc).replace(tzinfo=None)
    week_utc = local_week.astimezone(timezone.utc).replace(tzinfo=None)
    return local_now, today_utc, week_utc


def remove_accents(input_str: str) -> str:
    """Loại bỏ dấu tiếng Việt để xuất tương thích hoàn hảo font chuẩn PDF Type 1 (Helvetica)."""
    if not input_str:
        return ""
    s = input_str.replace("đ", "d").replace("Đ", "D")
    nfkd = unicodedata.normalize("NFKD", s)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def sanitize_pdf_text(text: str) -> str:
    clean = remove_accents(str(text))
    return clean.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def generate_weekly_report_pdf(child_name: str, stats: dict) -> bytes:
    """Sinh tệp PDF 1.4 chuẩn bằng pure-Python không phụ thuộc thư viện ngoài."""
    stream_ops = []

    def op(s: str):
        stream_ops.append(s)

    # 1. Header Banner
    op("0.13 0.39 0.92 rg")  # Primary blue
    op("40 750 515 52 re f") # Filled rectangle
    op("BT /F2 16 Tf 1 1 1 rg 55 770 Td (CHILDGUARD - BAO CAO HOAT DONG TUAN) Tj ET")
    op("BT /F1 10 Tf 0.9 0.95 1 rg 55 756 Td (He thong giam sat va bao ve an toan tre em tren khong gian mang) Tj ET")

    # 2. Child info & Metadata
    child_clean = sanitize_pdf_text(child_name or "Be")
    now_str = datetime.utcnow().strftime("%d/%m/%Y")
    op("BT /F2 11 Tf 0.1 0.1 0.1 rg 40 720 Td (Thong tin hoc sinh / Thiet bi:) Tj ET")
    op(f"BT /F1 11 Tf 0.2 0.2 0.2 rg 190 720 Td ({child_clean}) Tj ET")

    op("BT /F2 11 Tf 0.1 0.1 0.1 rg 340 720 Td (Thoi gian xuat:) Tj ET")
    op(f"BT /F1 11 Tf 0.2 0.2 0.2 rg 430 720 Td ({now_str}) Tj ET")

    # Đường kẻ ngang phân cách
    op("0.85 0.88 0.92 RG 1 w 40 708 m 555 708 l S")

    # 3. Summary Cards (3 cards)
    # Card 1: Today Usage
    today_min = stats.get("today_screen_time_minutes", 0)
    quota = stats.get("daily_quota", 120)
    op("0.96 0.97 0.99 rg 40 640 160 55 re f")
    op("0.85 0.88 0.92 RG 1 w 40 640 160 55 re S")
    op("BT /F1 9 Tf 0.4 0.4 0.4 rg 50 678 Td (THOI GIAN DUNG HOM NAY) Tj ET")
    op(f"BT /F2 15 Tf 0.13 0.39 0.92 rg 50 658 Td ({today_min:.1f} / {quota} phut) Tj ET")

    # Card 2: Blocked Apps
    blocked_apps = stats.get("top_blocked_apps", [])
    total_blocked_apps = sum(a.get("count", 0) for a in blocked_apps)
    op("0.96 0.97 0.99 rg 215 640 160 55 re f")
    op("0.85 0.88 0.92 RG 1 w 215 640 160 55 re S")
    op("BT /F1 9 Tf 0.4 0.4 0.4 rg 225 678 Td (UNG DUNG BI CHAN) Tj ET")
    op(f"BT /F2 15 Tf 0.85 0.2 0.2 rg 225 658 Td ({len(blocked_apps)} app ({total_blocked_apps} lan)) Tj ET")

    # Card 3: Blocked Webs
    blocked_webs = stats.get("top_blocked_domains", [])
    total_blocked_webs = sum(w.get("count", 0) for w in blocked_webs)
    op("0.96 0.97 0.99 rg 395 640 160 55 re f")
    op("0.85 0.88 0.92 RG 1 w 395 640 160 55 re S")
    op("BT /F1 9 Tf 0.4 0.4 0.4 rg 405 678 Td (TEN MIEN BI CHAN) Tj ET")
    op(f"BT /F2 15 Tf 0.92 0.55 0.1 rg 405 658 Td ({len(blocked_webs)} domain ({total_blocked_webs} lan)) Tj ET")

    # 4. Weekly Bar Chart
    op("BT /F2 12 Tf 0.1 0.1 0.1 rg 40 610 Td (Bieu do thoi luong su dung 7 ngay qua (phut)) Tj ET")
    op("0.98 0.98 0.99 rg 40 470 515 125 re f")
    op("0.88 0.90 0.94 RG 1 w 40 470 515 125 re S")
    # Trục cơ sở Y=495
    op("0.8 0.8 0.8 RG 1 w 60 495 m 535 495 l S")

    daily_list = stats.get("daily_list", [])
    max_val = max([d.get("minutes", 0) for d in daily_list] + [quota, 60.0])
    bar_width = 32
    spacing = 65

    for idx, item in enumerate(daily_list[:7]):
        day_str = sanitize_pdf_text(item.get("day", ""))
        mins = float(item.get("minutes", 0))
        bar_h = min(80, max(4, int((mins / max_val) * 80))) if mins > 0 else 0
        bx = 75 + idx * spacing

        # Cột biểu đồ
        if mins > 0:
            if mins > quota:
                op(f"0.9 0.25 0.25 rg {bx} 495 {bar_width} {bar_h} re f")
            else:
                op(f"0.15 0.45 0.95 rg {bx} 495 {bar_width} {bar_h} re f")
            op(f"BT /F2 8 Tf 0.2 0.2 0.2 rg {bx} {495 + bar_h + 4} Td ({mins:.0f}p) Tj ET")
        else:
            op(f"0.85 0.85 0.85 rg {bx} 495 {bar_width} 2 re f")

        op(f"BT /F1 9 Tf 0.4 0.4 0.4 rg {bx + 2} 482 Td ({day_str}) Tj ET")

    # 5. Top 5 Blocked Apps & Top 5 Blocked Webs
    table_y = 430
    op(f"BT /F2 11 Tf 0.1 0.1 0.1 rg 40 {table_y} Td (Top ung dung bi chan nhieu nhat) Tj ET")
    op(f"BT /F2 11 Tf 0.1 0.1 0.1 rg 295 {table_y} Td (Top ten mien bi chan nhieu nhat) Tj ET")

    table_y -= 14
    # Header bảng app
    op(f"0.92 0.94 0.97 rg 40 {table_y} 245 18 re f")
    op(f"BT /F2 9 Tf 0.2 0.2 0.2 rg 45 {table_y + 5} Td (STT) Tj ET")
    op(f"BT /F2 9 Tf 0.2 0.2 0.2 rg 75 {table_y + 5} Td (Ten ung dung / Process) Tj ET")
    op(f"BT /F2 9 Tf 0.2 0.2 0.2 rg 235 {table_y + 5} Td (So lan) Tj ET")

    # Header bảng web
    op(f"0.92 0.94 0.97 rg 295 {table_y} 260 18 re f")
    op(f"BT /F2 9 Tf 0.2 0.2 0.2 rg 300 {table_y + 5} Td (STT) Tj ET")
    op(f"BT /F2 9 Tf 0.2 0.2 0.2 rg 330 {table_y + 5} Td (Ten mien website) Tj ET")
    op(f"BT /F2 9 Tf 0.2 0.2 0.2 rg 505 {table_y + 5} Td (So lan) Tj ET")

    row_y = table_y - 18
    for i in range(5):
        bg = "0.98 0.98 0.99" if i % 2 == 1 else "1 1 1"
        op(f"{bg} rg 40 {row_y} 245 16 re f")
        op(f"{bg} rg 295 {row_y} 260 16 re f")

        # Row App
        if i < len(blocked_apps):
            app = blocked_apps[i]
            a_name = sanitize_pdf_text(app.get("name", ""))[:24]
            a_cnt = str(app.get("count", 0))
            op(f"BT /F1 8 Tf 0.3 0.3 0.3 rg 48 {row_y + 4} Td ({i+1}) Tj ET")
            op(f"BT /F1 8 Tf 0.1 0.1 0.1 rg 75 {row_y + 4} Td ({a_name}) Tj ET")
            op(f"BT /F2 8 Tf 0.8 0.1 0.1 rg 245 {row_y + 4} Td ({a_cnt}) Tj ET")
        else:
            op(f"BT /F1 8 Tf 0.6 0.6 0.6 rg 75 {row_y + 4} Td (-) Tj ET")

        # Row Web
        if i < len(blocked_webs):
            web = blocked_webs[i]
            w_name = sanitize_pdf_text(web.get("name", ""))[:28]
            w_cnt = str(web.get("count", 0))
            op(f"BT /F1 8 Tf 0.3 0.3 0.3 rg 303 {row_y + 4} Td ({i+1}) Tj ET")
            op(f"BT /F1 8 Tf 0.1 0.1 0.1 rg 330 {row_y + 4} Td ({w_name}) Tj ET")
            op(f"BT /F2 8 Tf 0.8 0.4 0.0 rg 515 {row_y + 4} Td ({w_cnt}) Tj ET")
        else:
            op(f"BT /F1 8 Tf 0.6 0.6 0.6 rg 330 {row_y + 4} Td (-) Tj ET")

        row_y -= 16

    # 6. Footer Note
    op("0.85 0.88 0.92 RG 1 w 40 80 m 555 80 l S")
    op("BT /F1 8 Tf 0.5 0.5 0.5 rg 40 68 Td (Bao cao duoc tao tu dong tu co so du lieu ChildGuard Gateway. Thoi han luu tru du lieu nhat ky: 90 ngay.) Tj ET")
    op("BT /F1 8 Tf 0.5 0.5 0.5 rg 40 56 Td (Tuan thu quy dinh ve bao ve du lieu va an toan thong tin cho tre em tren moi truong mang theo Nghi dinh 13/2023/ND-CP.) Tj ET")

    content_str = "\n".join(stream_ops)
    content_bytes = content_str.encode("latin-1", errors="replace")

    # Build PDF Objects
    objects = []
    # 1: Catalog
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    # 2: Pages
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    # 3: Page
    objects.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595.28 841.89] "
        b"/Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>"
    )
    # 4: Font F1 (Helvetica)
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    # 5: Font F2 (Helvetica-Bold)
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
    # 6: Contents Stream
    objects.append(
        f"<< /Length {len(content_bytes)} >>\nstream\n".encode("ascii")
        + content_bytes
        + b"\nendstream"
    )

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]

    for i, obj in enumerate(objects, 1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode("ascii"))
        out.write(obj)
        out.write(b"\nendobj\n")

    xref_pos = out.tell()
    out.write(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    out.write(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.write(f"{off:010d} 00000 n \n".encode("ascii"))

    out.write(b"trailer\n")
    out.write(f"<< /Size {len(offsets)} /Root 1 0 R >>\n".encode("ascii"))
    out.write(b"startxref\n")
    out.write(f"{xref_pos}\n".encode("ascii"))
    out.write(b"%%EOF\n")

    return out.getvalue()


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

    local_now, today_start_utc, week_start_utc = _local_period_bounds()
    local_today_start = local_now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Lấy tất cả sự kiện trong vòng 7 ngày gần nhất
    events = (
        db.query(models.EventLog)
        .filter(models.EventLog.child_id == child_id, models.EventLog.created_at >= week_start_utc)
        .order_by(models.EventLog.created_at.desc(), models.EventLog.id.desc())
        .all()
    )

    today_screen_time_sec = 0
    blocked_apps_counter = Counter()
    blocked_domains_counter = Counter()

    # Biểu đồ theo tuần: 7 ngày (dd/mm)
    days_keys = [(local_today_start - timedelta(days=i)).strftime("%d/%m") for i in range(6, -1, -1)]
    daily_usage = {k: 0 for k in days_keys}

    # Biểu đồ theo ngày: 24 mốc giờ hôm nay (00:00 -> 23:00)
    hourly_usage = {f"{h:02d}:00": 0 for h in range(24)}

    # Khung giờ buổi trong ngày cho trẻ (Sáng, Chiều, Tối, Đêm)
    morning_sec = 0     # 06:00 - 12:00
    afternoon_sec = 0   # 12:00 - 18:00
    evening_sec = 0     # 18:00 - 22:00
    night_sec = 0       # 22:00 - 06:00

    category_day_seconds: dict[str, Counter] = defaultdict(Counter)
    category_day_queries: dict[str, Counter] = defaultdict(Counter)
    category_domain_seconds: dict[str, Counter] = defaultdict(Counter)
    category_domain_queries: dict[str, Counter] = defaultdict(Counter)
    seen_domain_minutes: set[tuple[str, str, str]] = set()

    for ev in events:
        local_created_at = utc_naive_to_report_time(ev.created_at)
        day_str = local_created_at.strftime("%d/%m")
        # Chỉ screen_time do heartbeat tạo từ bộ đếm authoritative của Agent.
        # Không cộng app_stop vì nhiều process chạy đồng thời sẽ phóng đại thời gian.
        if ev.event_type == "screen_time":
            if day_str in daily_usage:
                daily_usage[day_str] += ev.duration_sec
            if ev.created_at >= today_start_utc:
                today_screen_time_sec += ev.duration_sec
                hour_key = local_created_at.strftime("%H:00")
                if hour_key in hourly_usage:
                    hourly_usage[hour_key] += ev.duration_sec

                ev_hour = local_created_at.hour
                if 6 <= ev_hour < 12:
                    morning_sec += ev.duration_sec
                elif 12 <= ev_hour < 18:
                    afternoon_sec += ev.duration_sec
                elif 18 <= ev_hour < 22:
                    evening_sec += ev.duration_sec
                else:
                    night_sec += ev.duration_sec

        elif ev.event_type == "blocked_app" and ev.subject:
            blocked_apps_counter[normalize_app_subject(ev.subject)] += 1
        elif ev.event_type == "blocked_domain" and ev.subject:
            blocked_domains_counter[normalize_domain_subject(ev.subject)] += 1

        if ev.event_type == "domain_query" and ev.subject:
            domain = normalize_domain_subject(ev.subject)
            category = classify_domain(domain)
            category_domain_queries[category][domain] += 1
            category_day_queries[category][day_str] += 1
            # DNS query không chứng minh tab đang được xem bao lâu. Chỉ hiển thị
            # số truy vấn; duration chỉ được tính nếu một nguồn đo chủ động gửi lên.
            activity_seconds = max(0, ev.duration_sec)
            category_day_seconds[category][day_str] += activity_seconds
            category_domain_seconds[category][domain] += activity_seconds

    # Recent activity is independent of the seven-day chart window. This keeps
    # the table useful even when the newest event is older than seven days.
    newest_events = (
        db.query(models.EventLog)
        .filter(models.EventLog.child_id == child_id)
        .order_by(models.EventLog.created_at.desc(), models.EventLog.id.desc())
        .limit(20)
        .all()
    )
    recent_events = [
        {
            "type": ev.event_type,
            "subject": ev.subject,
            "duration_sec": ev.duration_sec,
            "time": utc_naive_to_report_time(ev.created_at).strftime("%H:%M:%S %d/%m/%Y"),
        }
        for ev in newest_events
    ]

    # Chuyển đổi sang phút
    daily_minutes = {k: round(v / 60, 1) for k, v in daily_usage.items()}
    hourly_minutes = {k: round(v / 60, 1) for k, v in hourly_usage.items()}
    today_screen_time_minutes = round(today_screen_time_sec / 60, 1)
    remaining_minutes = max(0, round(daily_quota - today_screen_time_minutes, 1))

    # Top 10 ứng dụng và Top 10 tên miền bị chặn kèm số lần
    top_apps_raw = sorted(blocked_apps_counter.items(), key=lambda item: (-item[1], item[0]))[:10]
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

    top_domains_raw = sorted(blocked_domains_counter.items(), key=lambda item: (-item[1], item[0]))[:10]
    max_domain_count = top_domains_raw[0][1] if top_domains_raw else 1
    top_blocked_domains = [
        {
            "rank": idx + 1,
            "name": name,
            "count": count,
            "percent": min(100, round((count / max_domain_count) * 100)),
        }
        for idx, (name, count) in enumerate(top_domains_raw)
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

    website_category_usage = []
    for definition in CATEGORY_DEFINITIONS:
        key = definition["key"]
        daily = [
            {
                "day": day,
                "minutes": round(category_day_seconds[key][day] / 60, 1),
                "queries": category_day_queries[key][day],
            }
            for day in days_keys
        ]
        domains = [
            {
                "name": domain,
                "minutes": round(seconds / 60, 1),
                "queries": category_domain_queries[key][domain],
            }
            for domain, seconds in sorted(
                category_domain_seconds[key].items(),
                key=lambda item: (-item[1], item[0]),
            )
        ]
        website_category_usage.append(
            {
                **definition,
                "total_minutes": round(sum(category_day_seconds[key].values()) / 60, 1),
                "total_queries": sum(category_day_queries[key].values()),
                "daily": daily,
                "domains": domains,
            }
        )

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
        "top_blocked_domains": top_blocked_domains,
        "recent_events": recent_events,
        "website_category_usage": website_category_usage,
        "website_category_days": days_keys,
        "report_timezone": "GMT+7 (Asia/Ho_Chi_Minh)",
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


@router.get("/reports/{child_id}/pdf")
def export_child_weekly_report_pdf(child_id: str, db: Session = Depends(get_db)):
    """Xuất file PDF báo cáo tuần cho một trẻ."""
    child = db.get(models.Child, child_id)
    if child is None:
        raise HTTPException(status_code=404, detail="child_not_found")
    stats = get_child_stats_summary(child_id, db)
    pdf_bytes = generate_weekly_report_pdf(child.display_name, stats)
    filename = f"childguard_weekly_report_{child.id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
