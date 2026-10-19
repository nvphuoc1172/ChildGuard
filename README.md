# ChildGuard

ChildGuard gồm FastAPI Server/Dashboard và Windows Agent. Agent đo screen-time theo thời gian hoạt động thực, không cộng thời lượng của các tiến trình chạy song song; truy vấn DNS chỉ dùng để phân loại/chặn và không được quy đổi thành thời gian duyệt web.

## Cài Agent trên Windows trong 15 phút

Yêu cầu: Windows 10/11 64-bit, Python 3.11–3.13, tài khoản Administrator, mã ghép đôi còn hạn và file CA tại `agent\certs\ogk-ca.crt`.

1. Tải/copy repository vào máy trẻ. Mở PowerShell bằng **Run as administrator**.
2. Tạo mã ghép đôi cho đúng trẻ trên Dashboard.
3. Chạy:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   cd <THU_MUC_CHILDGUARD>\agent
   .\install.ps1
   ```

4. Nhập IP server, mã ghép đôi và tạo mật khẩu quản trị riêng tối thiểu 12 ký tự.
5. Kiểm tra:

   ```powershell
   Get-Service ChildGuardAgent
   Get-ScheduledTask "ChildGuard Tray UI"
   Get-Content .\agent_state\service.log -Tail 30
   ```

Dịch vụ `ChildGuardAgent` chạy nền, tự khởi động cùng Windows và được SCM khởi động lại sau lỗi. TrayUI chạy trong phiên đăng nhập của trẻ và có khóa single-instance.

## Quản lý an toàn

Mở PowerShell Administrator tại thư mục `agent`:

```powershell
.\.venv\Scripts\python.exe .\agentctl.py stop
.\.venv\Scripts\python.exe .\agentctl.py restart
.\uninstall.ps1
```

Lệnh dừng/restart/gỡ yêu cầu mật khẩu quản trị ChildGuard. Chỉ hash PBKDF2 của mật khẩu được lưu tại `%ProgramData%\ChildGuard\admin.json`, ACL chỉ cho `SYSTEM` và `Administrators`.

Giới hạn bảo mật của Windows: một người đã có quyền Administrator luôn có thể dùng Service Control Manager hoặc thay file hệ thống để vô hiệu hóa bất kỳ dịch vụ nào. Cơ chế trên ngăn tài khoản trẻ tiêu chuẩn và bảo vệ quy trình quản lý thông thường; nó không thể chống lại một quản trị viên cục bộ. Không cấp quyền Administrator cho tài khoản trẻ.

## Phát triển an toàn trên cùng máy

Không cài Service khi đang thử logic khóa trên máy phát triển. Chạy:

```powershell
python agent\run_agent.py --ca-cert agent\certs\ogk-ca.crt --dev-safe-lock --pair
```

Chế độ này chỉ gọi khóa Windows một lần cho mỗi đợt vi phạm. Nút **Mở khóa máy** trên Dashboard xóa trạng thái khóa của Agent.

## Quyền riêng tư

- [Bảng dữ liệu, mục đích, thời hạn và người xem](docs/PRIVACY.md)
- [Phiên bản dành cho trẻ](docs/PRIVACY-for-child.md)

## Sau khi tắt và bật lại máy Windows

Có hai cách vận hành Agent:

### Chạy thủ công để phát triển

Nếu chỉ chạy:

```powershell
python agent\run_agent.py --ca-cert agent\certs\ogk-ca.crt
```

thì sau khi shutdown và bật máy lại, người phát triển phải chạy lại lệnh trên. Không cần tạo mã ghép đôi mới: `agent\agent_state\device_token.json` giữ định danh thiết bị và refresh token để Agent tự xin access token mới.

Chỉ chạy `--pair` khi muốn chuyển máy sang trẻ khác, thay phiên ghép đôi, token/thiết bị đã bị phụ huynh thu hồi, database server bị tạo lại hoặc file trạng thái bị mất/hỏng:

```powershell
python agent\run_agent.py --ca-cert agent\certs\ogk-ca.crt --pair
```
Khi muốn dừng lại thì nhấn Crtl+C (chứ không tắt bằng nút X)
Ctrl+C
→ shutdown()
→ dns_proxy.stop()
→ WindowsDNSManager.restore()
→ trả DNS về cấu hình trước khi chạy Agent

### Đã cài Windows Service

Nếu đã chạy `agent\install.ps1`, sau khi bật máy không phải nhập lệnh và không phải ghép đôi lại:

- Windows tự khởi động service `ChildGuardAgent` chạy Agent Core dưới nền.
- Scheduled Task `ChildGuard Tray UI` mở giao diện khay sau khi người dùng đăng nhập.
- Agent dùng refresh token đã lưu để tự cấp lại access token.

Kiểm tra trạng thái:

```powershell
Get-Service ChildGuardAgent
Get-ScheduledTask "ChildGuard Tray UI"
```

## Khi Agent đóng hoặc crash đột ngột

Các nguyên nhân đã được xử lý gồm chạy trùng Agent/TrayUI, tranh cổng IPC/DNS, double-click mở trùng cửa sổ Tk và exception trong các vòng lặp Enforcer/heartbeat/WebSocket. Lần chạy thứ hai hiện thoát có thông báo thay vì làm hỏng instance đang chạy.

Khi chạy dưới Windows Service, Service Control Manager tự khởi động lại Agent sau lỗi với các mốc 5 giây, 15 giây và 60 giây. stdout/stderr được giữ tại:

```text
agent\agent_state\service.log
```

Đọc 100 dòng cuối hoặc theo dõi trực tiếp:

```powershell
Get-Content agent\agent_state\service.log -Tail 100
Get-Content agent\agent_state\service.log -Wait
```

Chẩn đoán và khởi động lại:

```powershell
Get-Service ChildGuardAgent
sc.exe query ChildGuardAgent
cd agent
.\.venv\Scripts\python.exe .\agentctl.py restart
```

Không thể khẳng định mọi crash đã được loại bỏ nếu chưa có traceback của lỗi thực tế. Cách vận hành tin cậy là dùng Windows Service: tiến trình được tự phục hồi và log không biến mất khi cửa sổ console đóng.

## Cài đặt Server

Xem hướng dẫn Debian/Ubuntu, VMware NAT, TLS SAN, firewall và kết nối Agent tại [README-SERVER.md](README-SERVER.md).


## Nếu có lỗi về rớt mạng sau khi chạy agent (và dừng đột ngột tiến trình agent)

- Thử vào Windows + r (nhập "cmd" nhấn enter): ping 8.8.8.8
- Nếu thấy:
```
Reply from 8.8.8.8: bytes=32 time=40ms TTL=116
```
- Mạng ok
- Tiếp tục ở cửa sổ cmd: ping google.com
```
Ping request could not find host google.com. Please check the name and try again. 
```
- Do cấu hình dns đã bị thay đổi thành 127.0.0.1.
- Ở Windows vào Setting -> Networks and Internet -> Change adapter options -> chuột phải vào mạng wifi -> properties -> IPv4 -> thêm 8.8.8.8 ở dòng cuối. 

- Hoặc cấu hình mặc định từ đầu:

```powershell
Get-NetAdapter |
    Where-Object Status -eq Up |
    Set-DnsClientServerAddress -ResetServerAddresses

Clear-DnsClientCache

Get-DnsClientServerAddress -AddressFamily IPv4 |
    Format-Table InterfaceAlias, ServerAddresses
```