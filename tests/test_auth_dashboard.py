from datetime import datetime, timedelta

from app import models, security


def test_dashboard_login_page_renders(client):
    response = client.get("/dashboard/login")
    assert response.status_code == 200
    assert "Đăng nhập phụ huynh" in response.text
    assert "ChildGuard" in response.text


def test_dashboard_register_page_renders(client):
    response = client.get("/dashboard/register")
    assert response.status_code == 200
    assert "Đăng ký tài khoản phụ huynh" in response.text
    assert "Tối thiểu 10 ký tự" in response.text


def test_dashboard_register_validation_password_too_short(client):
    response = client.post(
        "/dashboard/register",
        data={
            "email": "testshort@ogk.local",
            "full_name": "Phụ huynh Ngắn",
            "password": "123",
            "confirm_password": "123",
        },
    )
    assert response.status_code == 400
    assert "tối thiểu 10 ký tự" in response.text.lower()


def test_dashboard_register_validation_password_mismatch(client):
    response = client.post(
        "/dashboard/register",
        data={
            "email": "testmismatch@ogk.local",
            "full_name": "Phụ huynh Test",
            "password": "Password123456",
            "confirm_password": "DifferentPassword123",
        },
    )
    assert response.status_code == 400
    assert "không khớp" in response.text


def test_dashboard_register_success_and_redirect_to_login(client, db_session):
    response = client.post(
        "/dashboard/register",
        data={
            "email": "parent_new@ogk.local",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "registered=1" in response.headers["location"]
    assert "ogk_session" not in response.cookies

    # Kiểm tra bản ghi trong DB
    parent = db_session.query(models.Parent).filter(models.Parent.email == "parent_new@ogk.local").first()
    assert parent is not None
    assert security.verify_password("SecurePassword123!", parent.password_hash)

    # Đăng nhập bằng tài khoản vừa tạo thành công
    login_resp = client.post(
        "/dashboard/login",
        data={
            "email": "parent_new@ogk.local",
            "password": "SecurePassword123!",
        },
        follow_redirects=False,
    )
    assert login_resp.status_code == 302
    assert login_resp.headers["location"] == "/dashboard"
    assert "ogk_session" in login_resp.cookies


def test_dashboard_register_duplicate_email(client):
    client.post(
        "/dashboard/register",
        data={
            "email": "dup@ogk.local",
            "full_name": "Người thứ nhất",
            "password": "Password123456",
            "confirm_password": "Password123456",
        },
    )
    # Đăng ký lại cùng email
    dup_resp = client.post(
        "/dashboard/register",
        data={
            "email": "dup@ogk.local",
            "full_name": "Người thứ hai",
            "password": "Password123456",
            "confirm_password": "Password123456",
        },
    )
    assert dup_resp.status_code == 400
    assert "đã được sử dụng" in dup_resp.text


def test_dashboard_login_failure_and_lockout(client, db_session):
    # Tạo tài khoản thử nghiệm
    parent = models.Parent(
        email="locktest@ogk.local",
        password_hash=security.hash_password("SuperSecret123"),
        full_name="Bị Khóa",
        failed_login_attempts=0,
    )
    db_session.add(parent)
    db_session.commit()

    # Nhập sai 4 lần
    for i in range(4):
        res = client.post(
            "/dashboard/login",
            data={"email": "locktest@ogk.local", "password": "wrong_password"},
        )
        assert res.status_code == 401

    db_session.refresh(parent)
    assert parent.failed_login_attempts == 4
    assert parent.locked_until is None

    # Lần thứ 5 sai -> Khóa 15 phút
    res5 = client.post(
        "/dashboard/login",
        data={"email": "locktest@ogk.local", "password": "wrong_password"},
    )
    assert res5.status_code == 403
    assert "tạm khóa" in res5.text.lower() or "khóa 15 phút" in res5.text.lower()

    db_session.refresh(parent)
    assert parent.failed_login_attempts == 5
    assert parent.locked_until is not None
    assert parent.locked_until > datetime.utcnow()

    # Thử đăng nhập lại dù đúng mật khẩu nhưng đang bị khóa
    res_locked = client.post(
        "/dashboard/login",
        data={"email": "locktest@ogk.local", "password": "SuperSecret123"},
    )
    assert res_locked.status_code == 403


def test_dashboard_login_success_and_logout(client, db_session):
    parent = models.Parent(
        email="loginsuccess@ogk.local",
        password_hash=security.hash_password("ValidPassword123!"),
        full_name="Đăng Nhập Chuẩn",
        failed_login_attempts=2,
    )
    db_session.add(parent)
    db_session.commit()

    res = client.post(
        "/dashboard/login",
        data={"email": "loginsuccess@ogk.local", "password": "ValidPassword123!"},
        follow_redirects=False,
    )
    assert res.status_code == 302
    assert res.headers["location"] == "/dashboard"
    assert "ogk_session" in res.cookies

    # Đã reset failed_login_attempts
    db_session.refresh(parent)
    assert parent.failed_login_attempts == 0
    assert parent.locked_until is None

    # Test logout
    logout_res = client.get("/dashboard/logout", follow_redirects=False)
    assert logout_res.status_code == 302
    assert "logout=1" in logout_res.headers["location"]


def test_dashboard_quick_demo_login(client):
    res = client.post("/dashboard/quick-demo-login", follow_redirects=False)
    assert res.status_code == 302
    assert res.headers["location"] == "/dashboard"
    assert "ogk_session" in res.cookies


def test_api_auth_register_and_login(client):
    # API POST /auth/register
    reg_resp = client.post(
        "/auth/register",
        json={
            "email": "apiparent@ogk.local",
            "password": "StrongPassword999",
            "full_name": "API Parent",
        },
    )
    assert reg_resp.status_code == 201
    data = reg_resp.json()
    assert data["parent_email"] == "apiparent@ogk.local"
    assert "access_token" in data

    token = data["access_token"]

    # API GET /auth/me
    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "apiparent@ogk.local"

    # API POST /auth/login
    login_resp = client.post(
        "/auth/login",
        json={
            "email": "apiparent@ogk.local",
            "password": "StrongPassword999",
        },
    )
    assert login_resp.status_code == 200
    assert "access_token" in login_resp.json()


def test_full_flow_parent_login_enroll_and_monitor(client, db_session):
    """Full luồng: Đăng ký (chuyển về login) -> Đăng nhập phụ huynh -> Tab Lấy mã cho bé -> Bé nhập mã -> Theo dõi bé trên Dashboard."""
    # 1. Phụ huynh đăng ký tài khoản (chỉ cần thông tin cơ bản: email + password)
    reg = client.post(
        "/dashboard/register",
        data={
            "email": "flow_mom@ogk.local",
            "password": "PasswordStrong123",
            "confirm_password": "PasswordStrong123",
        },
        follow_redirects=False,
    )
    assert reg.status_code == 302
    assert "registered=1" in reg.headers["location"]
    assert "ogk_session" not in reg.cookies

    # 2. Phụ huynh đăng nhập từ màn hình login
    login_resp = client.post(
        "/dashboard/login",
        data={
            "email": "flow_mom@ogk.local",
            "password": "PasswordStrong123",
        },
        follow_redirects=False,
    )
    assert login_resp.status_code == 302
    assert login_resp.headers["location"] == "/dashboard"
    assert "ogk_session" in login_resp.cookies

    # 3. Phụ huynh vào tab riêng /dashboard/enroll để lấy mã ghép đôi
    enroll_tab_resp = client.get("/dashboard/enroll")
    assert enroll_tab_resp.status_code == 200
    assert "Lấy mã ghép đôi" in enroll_tab_resp.text
    assert "Sinh mã ghép đôi mới" in enroll_tab_resp.text

    # 4. Phụ huynh bấm sinh mã nhanh (không cần chọn ai, cho trẻ bất kỳ)
    gen_code_resp = client.post("/dashboard/enroll/generate", follow_redirects=False)
    assert gen_code_resp.status_code == 302
    location = gen_code_resp.headers["location"]
    assert "/dashboard/enroll?code=" in location

    # Tách mã ghép đôi từ URL redirect
    import urllib.parse
    parsed = urllib.parse.urlparse(location)
    params = urllib.parse.parse_qs(parsed.query)
    enroll_code = params["code"][0]
    assert len(enroll_code) == 8

    # 5. Mở lại tab enroll phụ huynh -> Hiển thị mã ghép đôi to rõ ràng
    enroll_view = client.get(f"/dashboard/enroll?code={enroll_code}")
    assert enroll_view.status_code == 200
    assert enroll_code in enroll_view.text
    assert "Mã đang hoạt động" in enroll_view.text

    # 5.1 Kiểm tra endpoint realtime status trả về thời gian còn lại
    status_resp = client.get(f"/dashboard/enroll/status?code={enroll_code}")
    assert status_resp.status_code == 200
    st_data = status_resp.json()
    assert st_data["code"] == enroll_code
    assert st_data["is_used"] is False
    assert st_data["is_expired"] is False
    assert st_data["rem_sec"] > 0
    assert st_data["status_text"] == "Đang chờ nhập"

    # 6. Máy của bé (Agent) gửi POST /enroll với mã này
    fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    agent_enroll = client.post(
        "/enroll",
        json={"code": enroll_code, "device_fingerprint": fingerprint},
    )
    assert agent_enroll.status_code == 201
    agent_data = agent_enroll.json()
    device_id = agent_data["device_id"]
    access_token = agent_data["access_token"]
    assert agent_data["policy_version"] == 1

    # 6.1 Kiểm tra endpoint realtime status sau khi bé đã nhập mã -> chuyển ngay sang Đã kết nối
    status_resp_after = client.get(f"/dashboard/enroll/status?code={enroll_code}")
    assert status_resp_after.status_code == 200
    st_data_after = status_resp_after.json()
    assert st_data_after["is_used"] is True
    assert st_data_after["status_text"] == "Đã kết nối"

    # 7. Máy của bé gửi heartbeat báo cáo sử dụng
    hb_resp = client.post(
        "/heartbeat",
        json={"policy_version": 1, "quota_used_seconds": 1800, "queued_event_count": 0},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert hb_resp.status_code == 200

    # 8. Phụ huynh mở lại Dashboard -> Thấy máy của bé hiển thị trực tuyến & có nút điều khiển khẩn cấp!
    dash_monitored = client.get("/dashboard")
    assert dash_monitored.status_code == 200
    assert device_id in dash_monitored.text
    assert "Trực tuyến" in dash_monitored.text
    assert "Khóa máy ngay lập tức" in dash_monitored.text
    assert "Cấp thêm giờ" in dash_monitored.text or "+15 phút" in dash_monitored.text


def test_enroll_status_api_unauthorized_and_invalid(client):
    # Chưa đăng nhập
    resp_unauth = client.get("/dashboard/enroll/status?code=NONEXIST", cookies={})
    assert resp_unauth.status_code == 401

    # Đăng nhập demo rồi gọi mã không tồn tại
    client.post("/dashboard/quick-demo-login")
    resp_notfound = client.get("/dashboard/enroll/status?code=INVALIDC")
    assert resp_notfound.status_code == 404


def test_enroll_with_custom_child_name_and_command_display(client):
    # Đăng nhập bằng tài khoản demo
    client.post("/dashboard/quick-demo-login")

    # Sinh mã với tên bé cụ thể
    gen_resp = client.post(
        "/dashboard/enroll/generate",
        data={"child_name": "Bé Bắp"},
        follow_redirects=False,
    )
    assert gen_resp.status_code == 302
    location = gen_resp.headers["location"]
    assert "/dashboard/enroll?code=" in location

    code = location.split("code=")[1]

    # Kiểm tra giao diện hiển thị tên bé và nút sao chép lệnh
    view_resp = client.get(f"/dashboard/enroll?code={code}")
    assert view_resp.status_code == 200
    assert "Bé Bắp" in view_resp.text
    assert code in view_resp.text
    assert "Sao chép lệnh" in view_resp.text
    assert "python agent/enroll.py" in view_resp.text
    assert "Tên của bé:" in view_resp.text

