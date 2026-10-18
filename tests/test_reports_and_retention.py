"""Unit test cho Báo cáo & Thống kê, Màn hình trẻ em, Retention 90 ngày và Xóa dữ liệu hai chiều.

Kiểm tra:
1. Báo cáo & Thống kê:
   - Biểu đồ thời lượng bé sử dụng máy theo ngày (24 giờ) và theo tuần (7 ngày).
   - Top 10 ứng dụng đã bị chặn kèm số lần chính xác.
   - Top 10 tên miền đã bị chặn kèm số lần chính xác.
2. Màn hình 'Hôm nay em đã dùng gì' cho trẻ:
   - Trả về giao diện thân thiện với hình ảnh và ngôn ngữ ấm áp.
   - Cho phép trẻ gửi yêu cầu xin thêm giờ từ màn hình.
3. Vòng đời dữ liệu & Retention 90 ngày:
   - Tự động dọn dẹp các bản ghi EventLog, AuditLog, Command, ChildRequest cũ quá 90 ngày.
   - Giữ nguyên các bản ghi trong vòng 90 ngày.
4. Nút 'Xóa toàn bộ dữ liệu của con tôi':
   - Xóa sạch dữ liệu sự kiện của con trên Server.
   - Phát lệnh khẩn cấp clear_data tới thiết bị của trẻ.
   - Agent nhận lệnh và xóa sạch hàng đợi sự kiện event_queue, reset screen-time về 0.
"""
from datetime import datetime, timedelta, timezone
import json
import uuid
from zoneinfo import ZoneInfo

import pytest

import sys
from pathlib import Path

agent_dir = Path(__file__).resolve().parent.parent / "agent"
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

from app import models
from app.domain_categories import CATEGORY_KEYS, DATA_FILE, classify_domain, load_domain_categories
from app.routers.reports import cleanup_old_logs, get_child_stats_summary
from storage import AgentStorage
from enforcer import PolicyEnforcer
from sync import SyncWorker


def _setup_child_and_device(db_session):
    parent = models.Parent(
        email=f"parent_{uuid.uuid4().hex[:8]}@ogk.local",
        password_hash="dummy",
        full_name="Nguyễn Văn Ba",
    )
    db_session.add(parent)
    db_session.flush()

    child = models.Child(parent_id=parent.id, display_name="Bé Minh An")
    db_session.add(child)
    db_session.flush()

    device = models.Device(
        child_id=child.id,
        device_name="Laptop Bé An",
        fingerprint_hash="fp_test_123456",
        status="active",
    )
    db_session.add(device)
    db_session.flush()

    policy = models.Policy(
        child_id=child.id,
        version=1,
        quota_json=json.dumps({"daily_minutes": 120}),
        schedule_json=json.dumps({"start_time": "07:00", "end_time": "21:30"}),
        app_rules_json=json.dumps({"mode": "blacklist", "blacklist": []}),
        domain_rules_json=json.dumps({"mode": "blacklist", "blacklist": []}),
        created_at=datetime.utcnow(),
    )
    db_session.add(policy)
    db_session.commit()
    return parent, child, device


def test_reports_hourly_and_weekly_breakdown(client, db_session):
    """Kiểm tra biểu đồ thời lượng theo ngày (24 giờ) và theo tuần (7 ngày)."""
    parent, child, device = _setup_child_and_device(db_session)

    report_tz = ZoneInfo("Asia/Ho_Chi_Minh")
    local_now = datetime.now(report_tz)
    local_today_start = local_now.replace(hour=0, minute=0, second=0, microsecond=0)

    def as_utc_naive(local_value):
        return local_value.astimezone(timezone.utc).replace(tzinfo=None)

    # Tạo 3 sự kiện screen_time hôm nay ở các khung giờ khác nhau: 08:00, 14:00, 20:00
    ev1 = models.EventLog(
        idempotency_key=f"ev_{uuid.uuid4().hex}",
        device_id=device.id,
        child_id=child.id,
        event_type="screen_time",
        duration_sec=1800,  # 30 phút
        created_at=as_utc_naive(local_today_start + timedelta(hours=8, minutes=15)),
    )
    ev2 = models.EventLog(
        idempotency_key=f"ev_{uuid.uuid4().hex}",
        device_id=device.id,
        child_id=child.id,
        event_type="screen_time",
        duration_sec=2700,  # 45 phút
        created_at=as_utc_naive(local_today_start + timedelta(hours=14, minutes=30)),
    )
    ev3 = models.EventLog(
        idempotency_key=f"ev_{uuid.uuid4().hex}",
        device_id=device.id,
        child_id=child.id,
        event_type="screen_time",
        duration_sec=900,   # 15 phút
        created_at=as_utc_naive(local_today_start + timedelta(hours=20, minutes=0)),
    )
    # Tạo sự kiện 2 ngày trước trong tuần
    ev_past = models.EventLog(
        idempotency_key=f"ev_{uuid.uuid4().hex}",
        device_id=device.id,
        child_id=child.id,
        event_type="screen_time",
        duration_sec=3600,  # 60 phút
        created_at=as_utc_naive((local_today_start - timedelta(days=2)) + timedelta(hours=10)),
    )
    db_session.add_all([ev1, ev2, ev3, ev_past])
    db_session.commit()

    resp = client.get(f"/reports/{child.id}")
    assert resp.status_code == 200
    data = resp.json()

    # Tổng thời gian hôm nay: 30 + 45 + 15 = 90 phút
    assert data["today_screen_time_minutes"] == 90.0
    assert data["remaining_minutes"] == 30.0  # 120 - 90 = 30 phút

    # Biểu đồ theo ngày (24 giờ): các khung giờ 08:00, 14:00, 20:00 có số phút chính xác
    hourly = data["hourly_minutes"]
    assert hourly["08:00"] == 30.0
    assert hourly["14:00"] == 45.0
    assert hourly["20:00"] == 15.0
    assert hourly["00:00"] == 0.0

    # Biểu đồ theo tuần: ngày 2 ngày trước có 60 phút, ngày hôm nay có 90 phút
    daily = data["daily_minutes"]
    today_key = local_today_start.strftime("%d/%m")
    past_key = (local_today_start - timedelta(days=2)).strftime("%d/%m")
    assert daily[today_key] == 90.0
    assert daily[past_key] == 60.0


def test_reports_top_10_blocked_apps_and_webs_with_counts(client, db_session):
    """Kiểm tra Top 10 ứng dụng và Top 10 tên miền bị chặn kèm số lần vi phạm chính xác."""
    parent, child, device = _setup_child_and_device(db_session)
    now = datetime.utcnow()

    # Tạo 12 ứng dụng bị chặn với số lần từ 12 xuống 1
    for i in range(1, 13):
        app_name = f"game_{i}.exe"
        count = i * 2
        for _ in range(count):
            ev = models.EventLog(
                idempotency_key=f"ev_app_{uuid.uuid4().hex}",
                device_id=device.id,
                child_id=child.id,
                event_type="blocked_app",
                subject=app_name,
                duration_sec=0,
                created_at=now - timedelta(hours=1),
            )
            db_session.add(ev)

    # Tạo 12 tên miền bị chặn với số lần khác nhau
    for i in range(1, 13):
        domain = f"badsite-{i}.com"
        count = i * 3
        for _ in range(count):
            ev = models.EventLog(
                idempotency_key=f"ev_web_{uuid.uuid4().hex}",
                device_id=device.id,
                child_id=child.id,
                event_type="blocked_domain",
                subject=domain,
                duration_sec=0,
                created_at=now - timedelta(hours=2),
            )
            db_session.add(ev)

    db_session.commit()

    resp = client.get(f"/reports/{child.id}")
    assert resp.status_code == 200
    data = resp.json()

    # Kiểm tra top_blocked_apps: đúng 10 mục
    top_apps = data["top_blocked_apps"]
    assert len(top_apps) == 10
    # Xếp hạng 1 phải là game_12.exe với 24 lần
    assert top_apps[0]["name"] == "game_12.exe"
    assert top_apps[0]["count"] == 24
    assert top_apps[1]["name"] == "game_11.exe"
    assert top_apps[1]["count"] == 22
    # Mục thứ 10 là game_3.exe với 6 lần
    assert top_apps[9]["name"] == "game_3.exe"
    assert top_apps[9]["count"] == 6

    # Kiểm tra top_blocked_domains: đúng 10 mục
    top_webs = data["top_blocked_domains"]
    assert len(top_webs) == 10
    # Xếp hạng 1 phải là badsite-12.com với 36 lần
    assert top_webs[0]["name"] == "badsite-12.com"
    assert top_webs[0]["count"] == 36
    assert top_webs[9]["name"] == "badsite-3.com"
    assert top_webs[9]["count"] == 9


def test_recent_events_contains_all_v2_event_types(client, db_session):
    """Nhật ký gần nhất không được lọc mất các sự kiện ngoài thời gian sử dụng."""
    _parent, child, device = _setup_child_and_device(db_session)
    now = datetime.utcnow()
    event_types = [
        "app_start", "app_stop", "domain_query", "blocked_app", "blocked_domain",
        "quota_warning", "locked", "unlock_request", "override_granted",
    ]
    for index, event_type in enumerate(event_types):
        subject = None
        if event_type in {"app_start", "app_stop", "blocked_app"}:
            subject = "Example.EXE"
        elif event_type in {"domain_query", "blocked_domain"}:
            subject = "www.example.com"
        db_session.add(
            models.EventLog(
                idempotency_key=f"recent_{event_type}_{uuid.uuid4().hex}",
                device_id=device.id,
                child_id=child.id,
                event_type=event_type,
                subject=subject,
                duration_sec=60 if event_type in {"app_stop", "quota_warning", "override_granted"} else 0,
                created_at=now - timedelta(seconds=index),
            )
        )
    db_session.commit()

    response = client.get(f"/reports/{child.id}")
    assert response.status_code == 200
    recent = response.json()["recent_events"]
    assert {event["type"] for event in recent} == set(event_types)
    assert next(event for event in recent if event["type"] == "locked")["subject"] is None


def test_website_classification_file_has_200_items_and_six_groups():
    with DATA_FILE.open("r", encoding="utf-8-sig") as handle:
        rows = [line for line in handle.read().splitlines()[1:] if line.strip()]
    assert len(rows) >= 200
    assert set(load_domain_categories().values()) == CATEGORY_KEYS
    assert classify_domain("portal.wikipedia.org") == "education"
    assert classify_domain("unknown-childguard-domain.example.net") == "unclassified"


def test_domain_activity_is_grouped_by_local_day_and_deduplicated_per_minute(db_session):
    _parent, child, device = _setup_child_and_device(db_session)
    report_tz = ZoneInfo("Asia/Ho_Chi_Minh")
    local_now = datetime.now(report_tz).replace(second=0, microsecond=0)

    def utc_naive(offset_minutes: int):
        return (local_now + timedelta(minutes=offset_minutes)).astimezone(timezone.utc).replace(tzinfo=None)

    for index, (domain, offset) in enumerate(
        [("wikipedia.org", 0), ("wikipedia.org", 0), ("wikipedia.org", 1), ("facebook.com", 2)]
    ):
        db_session.add(
            models.EventLog(
                idempotency_key=f"domain_activity_{index}_{uuid.uuid4().hex}",
                device_id=device.id,
                child_id=child.id,
                event_type="domain_query",
                subject=domain,
                duration_sec=0,
                created_at=utc_naive(offset),
            )
        )
    db_session.commit()

    stats = get_child_stats_summary(child.id, db_session)
    by_key = {item["key"]: item for item in stats["website_category_usage"]}
    assert by_key["education"]["total_minutes"] == 2.0
    assert by_key["social_network"]["total_minutes"] == 1.0
    assert by_key["education"]["domains"][0]["name"] == "wikipedia.org"
    assert by_key["education"]["domains"][0]["queries"] == 3


def test_recent_event_time_is_rendered_in_gmt_plus_7_and_not_limited_to_week(db_session):
    _parent, child, device = _setup_child_and_device(db_session)
    old_utc = datetime(2025, 1, 1, 9, 2, 0)
    db_session.add(
        models.EventLog(
            idempotency_key=f"old_recent_{uuid.uuid4().hex}",
            device_id=device.id,
            child_id=child.id,
            event_type="app_start",
            subject="svchost.exe",
            duration_sec=0,
            created_at=old_utc,
        )
    )
    db_session.commit()

    stats = get_child_stats_summary(child.id, db_session)
    assert stats["recent_events"][0]["time"] == "16:02:00 01/01/2025"


def test_reports_dashboard_shows_child_categories_and_live_recent_fragment(client, db_session):
    parent, child, device = _setup_child_and_device(db_session)
    from app import security

    client.cookies["ogk_session"] = security.create_parent_session(parent.id)
    db_session.add(
        models.EventLog(
            idempotency_key=f"dashboard_recent_{uuid.uuid4().hex}",
            device_id=device.id,
            child_id=child.id,
            event_type="domain_query",
            subject="wikipedia.org",
            duration_sec=0,
            created_at=datetime.utcnow(),
        )
    )
    db_session.commit()

    page = client.get(f"/dashboard/reports?child_id={child.id}")
    assert page.status_code == 200
    assert child.display_name in page.text
    for label in ("Giáo dục", "Giải trí", "Mạng xã hội", "Trò chơi", "Không phù hợp lứa tuổi", "Chưa phân loại"):
        assert label in page.text
    assert f"/dashboard/reports/recent-events?child_id={child.id}" in page.text

    fragment = client.get(f"/dashboard/reports/recent-events?child_id={child.id}")
    assert fragment.status_code == 200
    assert "domain_query" in fragment.text
    assert "wikipedia.org" in fragment.text
    assert "GMT+7" in fragment.text


def test_retention_cleanup_90_days(db_session):
    """Kiểm tra thời hạn lưu trữ log 90 ngày: dọn sạch bản ghi >90 ngày và giữ bản ghi <=90 ngày."""
    parent, child, device = _setup_child_and_device(db_session)
    now = datetime.utcnow()

    # 1. Bản ghi CŨ QUÁ 90 ngày (95 ngày trước)
    old_time = now - timedelta(days=95)
    ev_old = models.EventLog(
        idempotency_key="ev_old_95d",
        device_id=device.id,
        child_id=child.id,
        event_type="screen_time",
        duration_sec=1200,
        created_at=old_time,
    )
    audit_old = models.AuditLog(
        actor_type="parent",
        actor_id=parent.id,
        action="old_action",
        detail_json="{}",
        created_at=old_time,
    )
    cmd_old = models.Command(
        device_id=device.id,
        command_type="lock",
        payload_json="{}",
        created_at=old_time,
    )
    req_old = models.ChildRequest(
        child_id=child.id,
        device_id=device.id,
        request_type="grant_time",
        created_at=old_time,
    )
    db_session.add_all([ev_old, audit_old, cmd_old, req_old])

    # 2. Bản ghi MỚI TRONG VÒNG 90 ngày (20 ngày trước)
    recent_time = now - timedelta(days=20)
    ev_recent = models.EventLog(
        idempotency_key="ev_recent_20d",
        device_id=device.id,
        child_id=child.id,
        event_type="screen_time",
        duration_sec=800,
        created_at=recent_time,
    )
    audit_recent = models.AuditLog(
        actor_type="parent",
        actor_id=parent.id,
        action="recent_action",
        detail_json="{}",
        created_at=recent_time,
    )
    cmd_recent = models.Command(
        device_id=device.id,
        command_type="unlock",
        payload_json="{}",
        created_at=recent_time,
    )
    req_recent = models.ChildRequest(
        child_id=child.id,
        device_id=device.id,
        request_type="grant_time",
        created_at=recent_time,
    )
    db_session.add_all([ev_recent, audit_recent, cmd_recent, req_recent])
    db_session.commit()

    old_ev_id = ev_old.id
    old_audit_id = audit_old.id
    old_cmd_id = cmd_old.id
    old_req_id = req_old.id
    recent_ev_id = ev_recent.id
    recent_audit_id = audit_recent.id
    recent_cmd_id = cmd_recent.id
    recent_req_id = req_recent.id

    # Thực hiện tác vụ dọn dẹp log quá 90 ngày
    res = cleanup_old_logs(db_session, days=90)
    assert res["deleted_events"] >= 1
    assert res["deleted_audit"] >= 1
    assert res["deleted_commands"] >= 1
    assert res["deleted_requests"] >= 1

    # Dọn dẹp session identity map để query trực tiếp từ DB
    db_session.expunge_all()

    # Kiểm tra DB: bản ghi cũ phải biến mất
    assert db_session.query(models.EventLog).filter(models.EventLog.id == old_ev_id).first() is None
    assert db_session.query(models.AuditLog).filter(models.AuditLog.id == old_audit_id).first() is None
    assert db_session.query(models.Command).filter(models.Command.id == old_cmd_id).first() is None
    assert db_session.query(models.ChildRequest).filter(models.ChildRequest.id == old_req_id).first() is None

    # Bản ghi mới còn nguyên
    assert db_session.query(models.EventLog).filter(models.EventLog.id == recent_ev_id).first() is not None
    assert db_session.query(models.AuditLog).filter(models.AuditLog.id == recent_audit_id).first() is not None
    assert db_session.query(models.Command).filter(models.Command.id == recent_cmd_id).first() is not None
    assert db_session.query(models.ChildRequest).filter(models.ChildRequest.id == recent_req_id).first() is not None


def test_purge_child_data_server_and_agent_cache(client, db_session, tmp_path):
    """Kiểm tra nút 'Xóa toàn bộ dữ liệu của con tôi': xóa đồng thời trên Server và bộ đệm Agent."""
    parent, child, device = _setup_child_and_device(db_session)
    now = datetime.utcnow()

    # Tạo một số EventLog và ChildRequest trên server
    ev = models.EventLog(
        idempotency_key="ev_to_purge",
        device_id=device.id,
        child_id=child.id,
        event_type="screen_time",
        duration_sec=3600,
        created_at=now,
    )
    req = models.ChildRequest(
        child_id=child.id,
        device_id=device.id,
        request_type="grant_time",
        subject="30",
        created_at=now,
    )
    db_session.add_all([ev, req])
    db_session.commit()

    # Khởi tạo AgentStorage giả lập chứa các event chưa gửi và thời gian dùng tích lũy
    db_file = tmp_path / "agent_purge_test.db"
    agent_storage = AgentStorage(db_path=db_file)
    agent_storage.add_event("app_stop", subject="study.exe", duration_sec=120)
    agent_storage.add_event("blocked_app", subject="badapp.exe")
    agent_storage.add_screen_time(1800)  # 30 phút
    agent_storage.set_lock_status(True)

    # Đảm bảo trước khi xóa, Agent có dữ liệu đệm
    assert len(agent_storage.get_pending_events()) == 2
    assert agent_storage.get_screen_time_today() == 1800
    assert agent_storage.get_lock_status() is True

    # 1. Gọi API xóa dữ liệu trên Server: POST /reports/{child_id}/purge
    resp = client.post(f"/reports/{child.id}/purge")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["deleted_events"] >= 1
    assert data["devices_commanded"] == 1

    # Kiểm tra Server đã xóa sạch EventLog và ChildRequest của bé
    events_left = db_session.query(models.EventLog).filter(models.EventLog.child_id == child.id).count()
    requests_left = db_session.query(models.ChildRequest).filter(models.ChildRequest.child_id == child.id).count()
    assert events_left == 0
    assert requests_left == 0

    # Kiểm tra lệnh clear_data được tạo cho device
    cmd = (
        db_session.query(models.Command)
        .filter(models.Command.device_id == device.id, models.Command.command_type == "clear_data")
        .first()
    )
    assert cmd is not None

    # 2. Giả lập Agent nhận lệnh clear_data từ Server
    enforcer = PolicyEnforcer(storage=agent_storage, lock_checker=lambda: False, idle_getter=lambda: 0.0)
    sync_worker = SyncWorker(
        storage=agent_storage,
        enforcer=enforcer,
        state_config={"server": "localhost", "port": 8443, "device_id": device.id, "access_token": "dummy"},
        ca_cert_path="",
    )

    # SyncWorker thực thi lệnh clear_data
    sync_worker.execute_command(cmd.id, "clear_data", {})

    # 3. Kiểm tra Agent Storage đã được dọn sạch hoàn toàn:
    assert len(agent_storage.get_pending_events()) == 0
    assert agent_storage.get_screen_time_today() == 0
    assert agent_storage.get_lock_status() is False


def test_child_today_screen_and_request_time(client, db_session):
    """Kiểm tra màn hình 'Hôm nay em đã dùng gì' và chức năng xin thêm giờ của trẻ."""
    parent, child, device = _setup_child_and_device(db_session)

    # Truy cập màn hình Hôm nay em đã dùng gì: /dashboard/child/{child_id}/today
    resp = client.get(f"/dashboard/child/{child.id}/today")
    assert resp.status_code == 200
    html = resp.text

    # Kiểm tra tên bé và các thông điệp ấm áp
    assert child.display_name in html
    assert "Phút em đã sử dụng hôm nay" in html
    assert "3 bí quyết vàng để đôi mắt sáng" in html

    # Trẻ gửi yêu cầu xin thêm 15 phút từ màn hình này
    resp_req = client.post(
        "/today/request-time",
        data={
            "child_id": child.id,
            "minutes": 15,
            "reason": "Con đang làm dở bài vẽ tranh cô giáo giao",
        },
        follow_redirects=False,
    )
    assert resp_req.status_code == 302
    assert "requested=1" in resp_req.headers["location"]

    # Kiểm tra yêu cầu được lưu vào bảng ChildRequest
    req = (
        db_session.query(models.ChildRequest)
        .filter(models.ChildRequest.child_id == child.id)
        .first()
    )
    assert req is not None
    assert req.request_type == "grant_time"
    assert req.subject == "15"
    assert "Con đang làm dở bài vẽ" in req.reason
    assert req.status == "pending"


def test_weekly_report_pdf_generation_and_export_endpoints(client, db_session):
    """Kiểm tra xuất file PDF báo cáo tuần:
    1. Hàm pure-Python generate_weekly_report_pdf sinh tệp PDF 1.4 hợp lệ.
    2. Endpoint GET /reports/{child_id}/pdf trả về application/pdf và Content-Disposition attachment.
    3. Endpoint GET /dashboard/reports/export-pdf trên Dashboard trả về application/pdf.
    """
    from app.routers.reports import generate_weekly_report_pdf

    parent, child, device = _setup_child_and_device(db_session)

    dummy_stats = {
        "today_screen_time_minutes": 85.5,
        "daily_quota": 120,
        "daily_list": [
            {"day": "12/10", "minutes": 45.0},
            {"day": "13/10", "minutes": 60.0},
            {"day": "14/10", "minutes": 90.0},
            {"day": "15/10", "minutes": 130.0},
            {"day": "16/10", "minutes": 85.0},
            {"day": "17/10", "minutes": 110.0},
            {"day": "18/10", "minutes": 85.5},
        ],
        "top_blocked_apps": [
            {"name": "game.exe", "count": 14},
            {"name": "roblox.exe", "count": 8},
        ],
        "top_blocked_domains": [
            {"name": "facebook.com", "count": 22},
            {"name": "tiktok.com", "count": 17},
        ],
    }

    # 1. Kiểm tra cấu trúc binary của file PDF thuần Python
    pdf_bytes = generate_weekly_report_pdf("Nguyen Minh An", dummy_stats)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_bytes
    assert b"CHILDGUARD - BAO CAO HOAT DONG TUAN" in pdf_bytes
    assert b"Nguyen Minh An" in pdf_bytes

    # 2. Kiểm tra endpoint API GET /reports/{child_id}/pdf
    resp1 = client.get(f"/reports/{child.id}/pdf")
    assert resp1.status_code == 200
    assert resp1.headers["content-type"] == "application/pdf"
    assert "attachment" in resp1.headers["content-disposition"]
    assert resp1.content.startswith(b"%PDF-1.4")

    # Đăng nhập phụ huynh bằng session cookie cho Dashboard
    from app import security
    client.cookies["ogk_session"] = security.create_parent_session(parent.id)

    # 3. Kiểm tra endpoint Dashboard GET /dashboard/reports/export-pdf
    resp2 = client.get(f"/dashboard/reports/export-pdf?child_id={child.id}")
    assert resp2.status_code == 200
    assert resp2.headers["content-type"] == "application/pdf"
    assert "attachment" in resp2.headers["content-disposition"]
    assert resp2.content.startswith(b"%PDF-1.4")

    # 4. Kiểm tra trang HTML reports có nút tải PDF và nút in
    resp_html = client.get("/dashboard/reports")
    assert resp_html.status_code == 200
    assert "Xu\u1ea5t PDF B\u00e1o C\u00e1o Tu\u1ea7n" in resp_html.text
    assert "/dashboard/reports/export-pdf" in resp_html.text
    assert "window.print()" in resp_html.text

