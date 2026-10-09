# Hướng dẫn Cài đặt & Khởi chạy OGK-Agent trên Windows 10/11

Tài liệu này hướng dẫn chi tiết các bước triển khai Agent kiểm soát trên máy tính của trẻ.

---

## 1. Yêu cầu hệ thống
- Hệ điều hành: Windows 10 hoặc Windows 11 (64-bit).
- Python: Phiên bản 3.11, 3.12 hoặc 3.13.
- Quyền: Administrator (để khóa máy tính và mở cổng DNS 53).

---

## 2. Chuẩn bị môi trường

Mở **PowerShell (Run as Administrator)** tại thư mục `ChildGuard\agent`:

```powershell
cd D:\Projects\MMT-QuanLyTreEm\ChildGuard\agent

# Tạo môi trường ảo nếu chưa có
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Cài đặt các gói phụ thuộc
pip install -r requirements.txt
```

---

## 3. Ghép đôi thiết bị (Enrollment)

1. Trên máy chủ Debian hoặc Dashboard web phụ huynh (`http://<SERVER_IP>:8443/dashboard`), lấy **Mã ghép đôi** (8 ký tự). Hoặc chạy lệnh trên server:
   ```bash
   python -m scripts.create_enrollment_code --parent-email demo@ogk.local --child-name "Minh An"
   ```
2. Sao chép tệp chứng chỉ `ogk-ca.crt` từ server vào thư mục `agent/certs/ogk-ca.crt`.
3. Chạy lệnh ghép đôi trên máy Windows:
   ```powershell
   python enroll.py --server <IP_MÁY_CHỦ> --port 8443 --ca-cert certs\ogk-ca.crt
   ```
   *Nhập mã ghép đôi 8 ký tự khi được yêu cầu.*
   Thông tin xác thực sẽ được lưu an toàn tại `agent_state/device_token.json`.

---

## 4. Khởi chạy Dịch vụ Bảo vệ (OGK-Agent Core)

Dịch vụ này chạy ngầm thực thi các chính sách:
- **Policy Enforcer**: Quét tiến trình mỗi 2s, tắt ứng dụng bị cấm, đếm giờ dùng máy, khóa máy khi hết giờ hoặc nhận lệnh `LOCK`.
- **DNS Proxy 127.0.0.1:53**: Chặn các website nằm trong danh sách đen của phụ huynh.
- **Sync Worker**: Duy trì kết nối WebSocket thời gian thực (<5s độ trễ nhận lệnh) và nhịp tim 60s.
- **Local IPC Server**: Cung cấp dữ liệu cho Tray UI tại `127.0.0.1:48123`.

Lệnh chạy dịch vụ (mở PowerShell với quyền Administrator):
```powershell
python run_agent.py --ca-cert certs\ogk-ca.crt
```

---

## 5. Khởi chạy Giao diện Khay Hệ thống (Tray UI cho trẻ)

Giao diện hiển thị minh bạch cho trẻ em trong phiên đăng nhập:
```powershell
python tray\tray_app.py
```
- Biểu tượng khiên 🛡️ xuất hiện tại khay hệ thống (System Tray).
- Nhấp chuột phải để xem thời gian sử dụng còn lại hôm nay.
- Bấm **"Xem chính sách bảo vệ"** để xem minh bạch hạn mức, giờ giấc, ứng dụng và website bị hạn chế.
- Bấm **"Xin thêm giờ..."** để mở hộp thoại gửi yêu cầu cộng thêm 15/30/60 phút tới phụ huynh.

---

## 6. Kích hoạt Lọc Website (DNS Proxy)

Để toàn bộ trình duyệt trên máy đi qua bộ lọc DNS Proxy của ChildGuard:
```powershell
# Chuyển DNS của card mạng về 127.0.0.1
Get-NetAdapter | Where-Object Status -eq Up | Set-DnsClientServerAddress -ServerAddresses ("127.0.0.1")
```

Khi muốn khôi phục về DNS tự động (DHCP):
```powershell
Get-NetAdapter | Where-Object Status -eq Up | Set-DnsClientServerAddress -ResetServerAddresses
```
