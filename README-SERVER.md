# Cài đặt ChildGuard Server trên Debian/Ubuntu và kết nối Windows Agent

Tài liệu này dành cho mô hình phát triển sau:

- Máy thật: Windows 10/11, chạy OGK-Agent và VMware Workstation/Player.
- Máy ảo: Debian hoặc Ubuntu Server, chạy FastAPI, Dashboard và SQLite.
- Network Adapter của VM: **NAT**.
- Thiết bị khác trong LAN kết nối tới `https://<IP-WINDOWS>:8443`.
- VMware NAT chuyển tiếp TCP 8443 của Windows host vào TCP 8443 của VM.

Ví dụ dùng trong tài liệu:

| Thành phần | Địa chỉ ví dụ |
|---|---|
| Windows host trong LAN | `10.232.0.44` |
| Debian/Ubuntu VM trong mạng VMware NAT | `192.168.198.130` |
| Cổng HTTPS | `8443/TCP` |
| URL Dashboard từ LAN | `https://10.232.0.44:8443/dashboard` |

Thay toàn bộ địa chỉ ví dụ bằng địa chỉ thực tế. IP Windows do router cấp có thể thay đổi; nên đặt DHCP reservation trên router hoặc dùng hostname/DNS ổn định.

## 1. Hiểu đúng đường đi của kết nối NAT

```text
Windows Agent/LAN client
  -> https://10.232.0.44:8443
  -> Windows Firewall cho phép TCP 8443
  -> VMware NAT port forwarding
  -> 192.168.198.130:8443 trên VM
  -> UFW cho phép TCP 8443
  -> Uvicorn lắng nghe 0.0.0.0:8443
```

Ba thành phần phải đồng thời đúng: Windows Firewall, VMware NAT port-forward và UFW/Uvicorn trong VM. Chỉ mở firewall không tự tạo port-forward.

TLS SAN phải chứa đúng tên/IP mà client dùng trong URL. Với mô hình trên, SAN cần `IP:10.232.0.44`; không chỉ chứa IP riêng của VM. Có thể thêm cả IP VM để Windows host kiểm thử trực tiếp qua VMnet8.

## 2. Cấu hình VMware NAT và IP VM

Trong VMware, đặt Network Adapter của VM thành `NAT` và bật `Connected` cùng `Connect at power on`.

Khởi động VM, xác định tên card mạng:

```bash
ip -4 -br addr
ip route
```

Card thường là `ens33`, nhưng Ubuntu/Debian có thể dùng tên khác. Chỉ dùng `ens33` trong các lệnh dưới nếu nó thực sự tồn tại:

```bash
sudo dhclient -r ens33
sudo dhclient ens33
ip -4 -br addr
ip route
ping -c 3 8.8.8.8
ping -c 3 google.com
```

Nếu ping IP được nhưng không ping được tên miền, đó là lỗi DNS trong VM. Kiểm tra:

```bash
cat /etc/resolv.conf
resolvectl status 2>/dev/null || true
```

### Port-forward VMware NAT

Tạo quy tắc TCP:

```text
Host port:      8443
Protocol:       TCP
Virtual IP:     192.168.198.130
Virtual port:   8443
```

Với VMware Workstation Pro, mở `Edit -> Virtual Network Editor -> Change Settings`, chọn mạng NAT đang dùng (thường `VMnet8`), chọn `NAT Settings -> Port Forwarding -> Add`.

VMware Player có thể không cung cấp giao diện này. Khi đó cấu hình `vmnetnat.conf` phụ thuộc phiên bản VMware và vị trí cài đặt; ưu tiên dùng Virtual Network Editor của VMware thay vì chỉnh file thủ công. Sau khi thay đổi, restart dịch vụ VMware NAT hoặc reboot Windows.

Nên cấu hình DHCP reservation cho VM trong VMware NAT. Nếu IP VM đổi, port-forward vẫn trỏ vào IP cũ và kết nối sẽ timeout.

## 3. Mở Windows Firewall

Mở PowerShell bằng quyền Administrator:

```powershell
New-NetFirewallRule `
  -DisplayName "OGK Server 8443" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 8443 `
  -Action Allow
```

Kiểm tra:

```powershell
Get-NetFirewallRule -DisplayName "OGK Server 8443"
Get-NetTCPConnection -LocalPort 8443 -ErrorAction SilentlyContinue
```

Nếu Windows host đã có chương trình khác nghe cổng 8443, VMware NAT không thể sử dụng cổng đó. Dừng chương trình xung đột hoặc chọn một host port khác rồi dùng đúng port đó trong URL Agent.

## 4. Cài gói hệ thống trong Debian/Ubuntu

```bash
sudo apt update
sudo apt full-upgrade -y
sudo apt install -y \
  open-vm-tools \
  python3 python3-venv python3-pip \
  git curl openssl sqlite3 ufw rsync ca-certificates \
  openssh-server build-essential
```

`resolvconf` không bắt buộc trên mọi Ubuntu/Debian và có thể xung đột với `systemd-resolved`. Chỉ cài khi hệ thống thực sự dùng nó:

```bash
sudo apt install -y resolvconf
```

Bật SSH:

```bash
sudo systemctl enable --now ssh
sudo systemctl status ssh --no-pager
```

Mở UFW. Luôn cho phép SSH trước khi enable để tránh tự khóa mình:

```bash
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow 8443/tcp comment 'OGK server'
sudo ufw enable
sudo ufw status verbose
```

Đồng bộ thời gian, rất quan trọng đối với TLS và thời hạn token:

```bash
sudo timedatectl set-timezone Asia/Ho_Chi_Minh
sudo timedatectl set-ntp true
timedatectl
```

## 5. Kiểm tra SSH từ Windows

Từ Windows host, dùng IP riêng của VM vì host có thể truy cập mạng VMnet8 trực tiếp:

```powershell
ssh hzthuan@192.168.198.130
```

Nếu không kết nối được:

```powershell
Test-NetConnection 192.168.198.130 -Port 22
```

Trong VM:

```bash
sudo ss -lntp | grep ':22'
sudo journalctl -u ssh -n 100 --no-pager
```

## 6. Tạo cấu trúc thư mục server

```bash
sudo mkdir -p /opt/childguard/{app,certs,data}
sudo chown -R "$(whoami)":"$(whoami)" /opt/childguard
cd /opt/childguard
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip wheel
```

Đưa repository vào `/opt/childguard/app`. Có thể clone trực tiếp:

```bash
git clone <REPOSITORY_URL> /opt/childguard/app
```

Hoặc từ Windows dùng `scp`/`rsync`. Sau đó:

```bash
cd /opt/childguard/app
source /opt/childguard/.venv/bin/activate
pip install -r server/requirements.txt
```

Đặt đường dẫn database:

```bash
export OGK_DB_PATH=/opt/childguard/data/ogk.db
```

Khi triển khai bằng systemd ở phần sau, biến này được lưu trong service nên không phụ thuộc shell hiện tại.

## 7. Tạo CA nội bộ và chứng chỉ TLS có SAN

### 7.1 Chọn SAN

Trên Windows:

```powershell
ipconfig
```

Giả sử IP Windows mà Agent/LAN client truy cập là `10.232.0.44`. Trong VM:

```bash
cd /opt/childguard/certs
SERVER_IP=10.232.0.44
VM_IP=192.168.198.130
```

Nếu IP Windows thay đổi, xác minh TLS theo IP cũ sẽ thất bại. Giải pháp tốt nhất là DHCP reservation hoặc hostname ổn định có trong SAN.

### 7.2 Tạo CA một lần

Không tạo lại CA mỗi lần IP đổi; nếu tạo lại, phải phân phối lại `ogk-ca.crt` cho mọi Agent.

```bash
openssl genrsa -out ogk-ca.key 4096
openssl req -x509 -new -key ogk-ca.key -sha256 -days 3650 \
  -subj "/CN=OGK Lab CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ogk-ca.crt
```

### 7.3 Tạo private key và CSR server

```bash
openssl genrsa -out ogk.key 2048
openssl req -new -key ogk.key -subj "/CN=ogk-server" -out ogk.csr
```

### 7.4 Tạo file SAN

Lệnh này dùng được trên Debian và Ubuntu:

```bash
cat <<EOF | sudo tee /opt/childguard/certs/ogk.ext >/dev/null
subjectAltName=IP:${SERVER_IP},IP:${VM_IP},IP:127.0.0.1,DNS:ogk-server,DNS:ogk-server.local,DNS:localhost
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
```

Đảm bảo shell đã có `SERVER_IP` và `VM_IP`. Nếu dùng `sudo sh -c` trong shell khác, biến có thể không được truyền đúng; hãy đọc lại file:

```bash
cat /opt/childguard/certs/ogk.ext
```

### 7.5 Ký chứng chỉ server

```bash
cd /opt/childguard/certs
openssl x509 -req -in ogk.csr \
  -CA ogk-ca.crt -CAkey ogk-ca.key -CAcreateserial \
  -out ogk.crt -days 825 -sha256 -extfile ogk.ext

chmod 600 ogk-ca.key ogk.key
chmod 644 ogk-ca.crt ogk.crt
openssl verify -CAfile ogk-ca.crt ogk.crt
openssl x509 -in ogk.crt -noout -subject -issuer -dates -ext subjectAltName
```

Kết quả cần có:

```text
ogk.crt: OK
X509v3 Subject Alternative Name:
    IP Address:10.232.0.44, IP Address:192.168.198.130, ...
```

Tuyệt đối không copy `ogk-ca.key` hoặc `ogk.key` khỏi server và không commit chúng vào Git. Agent chỉ nhận `ogk-ca.crt`, là chứng chỉ công khai.

### Khi IP Windows thay đổi

Giữ nguyên `ogk-ca.key` và `ogk-ca.crt`, chỉ tạo lại CSR/chứng chỉ server với SAN mới, rồi restart Uvicorn. Sau đó Agent vẫn tin cùng CA.

## 8. Smoke test HTTPS trong VM

Thông thường nên chạy ứng dụng thật. Nếu cần cô lập lỗi TLS, tạo smoke test tạm:

```bash
source /opt/childguard/.venv/bin/activate
pip install fastapi 'uvicorn[standard]'

cat >/tmp/hello.py <<'EOF'
from fastapi import FastAPI
app = FastAPI()

@app.get('/ping')
def ping():
    return {'status': 'ok', 'service': 'ogk-smoke-test'}
EOF

cd /tmp
uvicorn hello:app --host 0.0.0.0 --port 8443 \
  --ssl-keyfile /opt/childguard/certs/ogk.key \
  --ssl-certfile /opt/childguard/certs/ogk.crt
```

Trong một terminal VM khác:

```bash
curl --cacert /opt/childguard/certs/ogk-ca.crt https://127.0.0.1:8443/ping
```

Dừng smoke test bằng `Ctrl+C` trước khi chạy server thật, nếu không sẽ có lỗi `Address already in use`.

## 9. Chạy ChildGuard Server thủ công

```bash
source /opt/childguard/.venv/bin/activate
export OGK_DB_PATH=/opt/childguard/data/ogk.db
cd /opt/childguard/app/server
uvicorn app.main:app --host 0.0.0.0 --port 8443 \
  --ssl-keyfile /opt/childguard/certs/ogk.key \
  --ssl-certfile /opt/childguard/certs/ogk.crt
```

Kiểm tra trong VM:

```bash
sudo ss -lntp | grep ':8443'
curl --cacert /opt/childguard/certs/ogk-ca.crt https://127.0.0.1:8443/ping
```

## 10. Chạy server tự động bằng systemd

Xác định user Linux hiện tại:

```bash
whoami
```

Thay `hzthuan` bên dưới nếu cần:

```bash
sudo tee /etc/systemd/system/childguard-server.service >/dev/null <<'EOF'
[Unit]
Description=ChildGuard FastAPI Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=hzthuan
Group=hzthuan
WorkingDirectory=/opt/childguard/app/server
Environment=OGK_DB_PATH=/opt/childguard/data/ogk.db
ExecStart=/opt/childguard/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8443 --ssl-keyfile /opt/childguard/certs/ogk.key --ssl-certfile /opt/childguard/certs/ogk.crt
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now childguard-server
sudo systemctl status childguard-server --no-pager
```

Theo dõi log:

```bash
sudo journalctl -u childguard-server -f
```

Sau khi cập nhật mã:

```bash
cd /opt/childguard/app
git pull
source /opt/childguard/.venv/bin/activate
pip install -r server/requirements.txt
sudo systemctl restart childguard-server
```

## 11. Copy CA và chuẩn bị Windows Agent

Trên Windows PowerShell:

```powershell
cd D:\Projects\MMT-QuanLyTreEm\ChildGuard\agent
python -m venv .venv
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Không cần cài thủ công một danh sách package khác với `requirements.txt`; đây là nguồn phụ thuộc chuẩn của Agent.

Tạo thư mục và copy CA từ VM qua SSH:

```powershell
New-Item -ItemType Directory -Force .\certs | Out-Null
scp hzthuan@192.168.198.130:/opt/childguard/certs/ogk-ca.crt .\certs\ogk-ca.crt
```

Kiểm tra import:

```powershell
python -c "import win32serviceutil, psutil, websockets, pystray, PIL; print('AGENT ENV OK')"
```

Kiểm tra cổng DNS 53 trước khi bật DNS proxy:

```powershell
Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue
```

Nếu có kết quả, tìm PID/chương trình đang chiếm cổng. Không tắt dịch vụ hệ thống một cách mù quáng.

## 12. Kiểm tra HTTPS từ Windows

Kiểm tra cổng qua địa chỉ Windows host/NAT:

```powershell
Test-NetConnection 10.232.0.44 -Port 8443
```

Kiểm tra TLS bằng đúng CA thay vì dùng `-k` hoặc tắt xác minh:

```powershell
python -c "import ssl,urllib.request; c=ssl.create_default_context(cafile=r'certs\ogk-ca.crt'); print(urllib.request.urlopen('https://10.232.0.44:8443/ping', context=c).read().decode())"
```

Kết quả mong đợi:

```json
{"status":"ok","service":"ogk-server"}
```

Nếu TCP thành công nhưng TLS báo `IP address mismatch`, SAN không chứa IP trong URL. Nếu TLS báo `unable to get local issuer certificate`, Agent đang dùng sai/mất `ogk-ca.crt`.

## 13. Dashboard và tài khoản

Chạy server:
```bash
source /opt/childguard/.venv/bin/activate
cd /opt/childguard/app/server
uvicorn app.main:app --host 0.0.0.0 --port 8443 \
  --ssl-keyfile /opt/childguard/certs/ogk.key \
  --ssl-certfile /opt/childguard/certs/ogk.crt
```
Mở:

```text
https://10.232.0.44:8443/dashboard
```

Tạo tài khoản phụ huynh thật trên trang đăng ký. Tài khoản demo phát triển mặc định là:

```text
Email:    demo@ogk.local
Password: admin123
```

Không dùng tài khoản demo trong triển khai thật. Khẳng định “mật khẩu bất kỳ” không còn đúng; endpoint đăng nhập hiện xác minh password hash.

## 14. Ghép đôi và chạy Agent

1. Đăng nhập Dashboard và tạo mã ghép đôi cho trẻ; mã có hạn 10 phút.
2. Chạy lần đầu:

   ```powershell
   cd D:\Projects\MMT-QuanLyTreEm\ChildGuard
   python agent\run_agent.py `
     --server 10.232.0.44 `
     --port 8443 `
     --ca-cert agent\certs\ogk-ca.crt
   ```

3. Nhập mã khi Agent hỏi. Không cần ghép đôi lại sau reboot.
4. Để cài chạy nền và tự khởi động:

   ```powershell
   cd agent
   .\install.ps1
   ```

Chỉ dùng `--pair` khi chuyển sang trẻ khác hoặc thay phiên ghép đôi hiện tại.

## 15. Database: sao lưu và phục hồi

Không xóa database chỉ vì server không khởi động. Trước tiên đọc log:

```bash
sudo journalctl -u childguard-server -n 200 --no-pager
sqlite3 /opt/childguard/data/ogk.db 'PRAGMA integrity_check;'
```

Sao lưu an toàn:

```bash
mkdir -p /opt/childguard/data/backups
sqlite3 /opt/childguard/data/ogk.db ".backup '/opt/childguard/data/backups/ogk-$(date +%F-%H%M%S).db'"
```

Chỉ khi chấp nhận mất toàn bộ tài khoản, trẻ, policy, token và log mới dừng server rồi xóa DB:

```bash
sudo systemctl stop childguard-server
rm -f /opt/childguard/data/ogk.db /opt/childguard/data/ogk.db-wal /opt/childguard/data/ogk.db-shm
sudo systemctl start childguard-server
```

Sau khi DB bị tạo lại, các Agent cũ không còn token hợp lệ và phải ghép đôi lại.

## 16. Lỗi thường gặp

| Triệu chứng | Nguyên nhân thường gặp | Kiểm tra/cách xử lý |
|---|---|---|
| `Test-NetConnection` thất bại | Thiếu VMware port-forward, Windows Firewall/UFW chặn, Uvicorn chưa chạy | Kiểm tra lần lượt Windows rule, VMware NAT rule, `ufw status`, `ss -lntp` |
| Windows host truy cập IP VM được nhưng thiết bị LAN không truy cập được | Chưa forward host port hoặc firewall chỉ cho profile sai | Dùng URL IP Windows, sửa NAT forwarding và firewall |
| `Connection refused` | Không có process nghe 8443 hoặc server crash | `systemctl status`, `journalctl`, `ss -lntp` |
| `Connection timed out` | Sai route/IP, firewall hoặc NAT rule trỏ IP VM cũ | `ip -4 -br addr`, kiểm tra DHCP reservation và NAT rule |
| `Address already in use` | Smoke test/server cũ đang giữ cổng | `sudo ss -lntp | grep :8443`, dừng process cũ |
| TLS `IP address mismatch` | IP client dùng không có trong SAN | Tạo lại cert server với SAN đúng, giữ nguyên CA |
| TLS `certificate has expired/not yet valid` | Cert hết hạn hoặc đồng hồ sai | `timedatectl`, `openssl x509 -dates` |
| TLS issuer/CA error | Copy sai CA hoặc vô tình tạo CA mới | So sánh SHA-256 của CA hai máy |
| `/heartbeat` trả 401 | Token bị thu hồi, DB server đã reset hoặc refresh token quá hạn 30 ngày | Xem log Agent; chỉ ghép đôi lại khi refresh không còn hợp lệ |
| WebSocket 403 | Access token cũ/sai thiết bị hoặc server DB đã thay | Agent sẽ refresh tự động; nếu tiếp diễn, kiểm tra `/auth/refresh` và DB |
| Dashboard bằng 0 dù Tray có thời gian | Server/Agent chưa chạy phiên bản mới hoặc heartbeat chưa tới | Restart server để migration chạy; chờ heartbeat và xem log sync |
| Screen-time tăng quá lớn | Server cũ cộng `app_stop` song song | Cập nhật server; báo cáo mới chỉ dùng delta `screen_time` từ heartbeat |
| DNS “Chưa phân loại” rất lớn | Phiên bản cũ quy query thành phút | Cập nhật server/template; bản mới chỉ hiển thị số query |
| SSH `Connection refused` | `openssh-server` chưa chạy hoặc UFW chặn | `systemctl enable --now ssh`, `ufw allow 22/tcp` |
| `Permission denied` với DB/cert | User systemd không sở hữu thư mục | `chown`, kiểm tra `User/Group` trong unit |
| `externally-managed-environment` | Pip chạy ngoài venv | `source /opt/childguard/.venv/bin/activate` |
| Agent không bind được UDP 53 | Cổng bị chiếm hoặc thiếu Administrator | Kiểm tra `Get-NetUDPEndpoint`; chạy/cài Agent bằng quyền phù hợp |
| Sau reboot Agent không chạy | Chỉ dùng chế độ thủ công, chưa cài Service | Chạy `agent\install.ps1`, kiểm tra `Get-Service ChildGuardAgent` |

## 17. Checklist hoàn tất

- [ ] VM dùng NAT và có IP ổn định.
- [ ] VMware forward Windows TCP 8443 vào VM TCP 8443.
- [ ] Windows Firewall, UFW và SSH đã cấu hình.
- [ ] Thời gian VM đồng bộ.
- [ ] Server requirements đã cài trong `/opt/childguard/.venv`.
- [ ] CA chỉ tạo một lần; private keys có quyền `600`.
- [ ] SAN chứa IP/hostname Agent thực sự sử dụng.
- [ ] `openssl verify` trả `OK`.
- [ ] systemd server ở trạng thái active.
- [ ] Windows TLS test `/ping` thành công bằng CA.
- [ ] Dashboard mở được qua IP Windows host.
- [ ] Agent ghép đôi thành công và heartbeat/WebSocket hoạt động.
- [ ] Windows Service và TrayUI tự chạy sau reboot nếu dùng chế độ triển khai.
