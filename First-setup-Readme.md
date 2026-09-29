#Set up cho máy Windows 10 chạy VMware máy ảo Debian 13 cho OCK-server

### Các gói cần thiết trên OCK-server
```bash
    sudo apt install -y python3 python3-venv python3-pip git curl openssl sqlite3 ufw rsync ca-certificates
    python3 --version     # Debian 13 → 3.13.x ; Debian 12 → 3.11.x
    openssl version
```
### Lệnh để đồng bộ thời gian
```bash
    sudo timedatectl set-timezone Asia/Ho_Chi_Minh
    sudo apt install -y systemd-timesyncd
    sudo systemctl enable --now systemd-timesyncd
    timedatectl
```
### Bật tường lửa
- Luôn allow 22 trước khi enable, kẻo tự khoá SSH của mình
```bash
    sudo ufw allow 22/tcp comment 'SSH'
    sudo ufw allow 8443/tcp comment 'OGK server'
    sudo ufw enable
    sudo ufw status
```
### Cấu trúc project được bảo mật trên OCK-server

/opt/childguard/
├── app/        ← mã nguồn (git clone repo vào đây, ở bước sau)
├── .venv/      ← Python virtualenv
├── certs/      ← khoá + chứng chỉ TLS (KHÔNG đưa vào Git)
└── data/       ← file SQLite (KHÔNG đưa vào Git)
```bash
sudo mkdir -p /opt/childguard/{app,certs,data}
sudo chown -R ogk:ogk /opt/childguard
cd /opt/childguard
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip wheel
```

### Tạo chứng chỉ TLS bằng CA nội bộ

Tại sao không dùng chứng chỉ tự ký đơn giản? Agent sẽ xác minh server bằng một CA cố định (certificate pinning theo CA) thay vì tắt kiểm tra — đúng yêu cầu "TLS 1.2+". Cách làm: tạo 1 CA nội bộ, dùng nó ký chứng chỉ server; máy Windows chỉ cần tin file ogk-ca.crt.

```bash

cd /opt/childguard/certs
SERVER_IP=192.168.1.50        # <-- ĐỔI thành IP thật của VM

# 1) CA nội bộ (hiệu lực 10 năm)
openssl genrsa -out ogk-ca.key 4096
openssl req -x509 -new -key ogk-ca.key -sha256 -days 3650 \
  -subj "/CN=OGK Lab CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ogk-ca.crt

# 2) Khoá + yêu cầu ký của server
openssl genrsa -out ogk.key 2048
openssl req -new -key ogk.key -subj "/CN=ogk-server" -out ogk.csr

# 3) File mở rộng (SAN bắt buộc: trình duyệt/Python chỉ nhìn SAN, không nhìn CN)
cat > ogk.ext <<EOF
subjectAltName=IP:${SERVER_IP},DNS:ogk-server,DNS:ogk-server.local,DNS:localhost
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

# 4) CA ký chứng chỉ server (825 ngày)
openssl x509 -req -in ogk.csr -CA ogk-ca.crt -CAkey ogk-ca.key -CAcreateserial \
  -out ogk.crt -days 825 -sha256 -extfile ogk.ext

# 5) Siết quyền + kiểm tra
chmod 600 ogk-ca.key ogk.key
openssl verify -CAfile ogk-ca.crt ogk.crt
openssl x509 -in ogk.crt -noout -ext subjectAltName

```
Cần thấy: ogk.crt: OK và dòng SAN có đúng IP của VM.

🔒 Chỉ file *ogk-ca.crt* (công khai) được phép rời khỏi VM. Hai file *.key không bao giờ copy sang máy khác, không commit lên Git. Nếu sau này đổi IP của VM → chạy lại bước 2–5 (CA giữ nguyên, agent không phải đổi gì).



### Checklist "môi trường đã sẵn sàng"

#	Việc cần đạt	Lệnh kiểm tra	Kết quả mong đợi
1	VM có IP cùng dải và ping được	ping 192.168.1.50 (Windows)	Có phản hồi
2	SSH vào VM	ssh ogk@192.168.1.50	Vào được dấu nhắc ogk@ogk-server
3	Giờ VM chuẩn	timedatectl	synchronized: yes, Asia/Ho_Chi_Minh
4	Python + venv trên VM	/opt/childguard/.venv/bin/python --version	3.11+
5	Chứng chỉ hợp lệ	openssl verify -CAfile ogk-ca.crt ogk.crt	ogk.crt: OK
6	Cổng 8443 thông từ Windows	Test-NetConnection 192.168.1.50 -Port 8443	TcpTestSucceeded : True
7	TLS xác minh bằng CA	lệnh Python ở B7(3)	In ra JSON status: ok
8	Thư viện agent	python -c "import win32serviceutil, ... ; print('AGENT ENV OK')"	AGENT ENV OK
9	Cổng 53 trống	Get-NetUDPEndpoint -LocalPort 53	Không in gì
10	Repo Git	git log --oneline	Có commit chore: init repository
11	Snapshot VM	VMware → Snapshot Manager	Có env-ready

Đủ 11 dòng → chuyển sang giai đoạn viết mã nguồn (server trước)

### Lỗi thường gặp và cách sửa
Triệu chứng	Nguyên nhân	Cách sửa
VM không có IP / IP dải khác Windows	Card mạng không phải Bridged, hoặc Bridged chọn nhầm adapter	A1: chọn Bridged; Virtual Network Editor → VMnet0 → chọn đúng card
ping được nhưng Test-NetConnection … 8443 False	ufw chưa mở, hoặc uvicorn bind 127.0.0.1	sudo ufw status; chạy uvicorn với --host 0.0.0.0
error: externally-managed-environment	Đang pip install ngoài venv	source /opt/childguard/.venv/bin/activate rồi cài lại
sudo: command not found / user không có sudo	Đã đặt root password khi cài	Xem ghi chú cuối A2
PowerShell: running scripts is disabled khi Activate	Execution Policy	Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
python mở Microsoft Store	Alias của Store chặn PATH	Tắt App execution aliases (B2)
import win32api → DLL load failed	pywin32 chưa đăng ký DLL	Admin: python .\.venv\Scripts\pywin32_postinstall.py -install
certificate verify failed: IP address mismatch	Đổi IP VM sau khi tạo chứng chỉ	Chạy lại A10 bước 2–5, không cần đổi CA
certificate has expired / not yet valid	Đồng hồ VM hoặc Windows sai	A6; Windows: Settings → Time → Sync now
Chứng chỉ báo hợp lệ trên Chrome nhưng Python lỗi	Chrome dùng kho Windows (đã import CA), Python dùng cafile	Kiểm tra đường dẫn cafile trỏ đúng ogk-ca.crt
scp: Permission denied (publickey/password)	Sai user/IP hoặc SSH chưa chạy	ssh ogk@IP thử trước; trên VM systemctl status ssh
Antivirus xoá/cảnh báo .exe sau này build bằng PyInstaller	False positive rất hay gặp với exe Python	Thêm thư mục C:\dev\ChildGuard vào Exclusions của Windows Security khi phát triển; ghi chú trong tài liệu nộp