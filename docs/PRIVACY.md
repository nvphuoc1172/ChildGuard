# Quyền riêng tư và thời hạn dữ liệu ChildGuard

ChildGuard chỉ thu thập dữ liệu cần thiết để ghép đôi thiết bị, thực thi chính sách và cung cấp báo cáo minh bạch. Thời hạn dưới đây là thời hạn tối đa; phụ huynh có thể dùng chức năng xóa dữ liệu của trẻ sớm hơn.

| Trường dữ liệu | Mục đích | Thời hạn lưu | Người được xem |
|---|---|---|---|
| `Parent.id`, email, họ tên | Định danh tài khoản quản lý và kiểm tra quyền với trẻ | Đến khi xóa tài khoản | Chính phụ huynh; quản trị viên hệ thống khi xử lý sự cố |
| `password_hash`, số lần đăng nhập sai, thời điểm khóa | Xác thực và chống dò mật khẩu; không lưu mật khẩu rõ | Đến khi đổi/xóa tài khoản | Server xác thực; không hiển thị trên dashboard |
| `Child.id`, tên hiển thị, giới tính tùy chọn | Hiển thị hồ sơ và gắn chính sách/báo cáo đúng trẻ | Đến khi phụ huynh xóa hồ sơ | Các phụ huynh có quyền với trẻ |
| `Device.id`, tên máy, `fingerprint_hash`, trạng thái | Ghép đúng máy, phát hiện sao chép phiên và thu hồi máy cũ | Đến khi xóa trẻ/thiết bị; bản ghi thu hồi tối đa 90 ngày | Phụ huynh có quyền; server |
| `last_seen_at`, quota ngày và số giây đã dùng | Trạng thái online và screen-time chính xác như TrayUI | Snapshot ngày hiện tại; log delta tối đa 90 ngày | Trẻ trên TrayUI; phụ huynh có quyền |
| Hash access/refresh token và thời hạn | Xác thực Agent mà không lưu token rõ trên server | Access 10 phút; refresh 30 ngày hoặc đến khi thu hồi | Chỉ server xác thực |
| Token rõ trong `agent_state/device_token.json` | Cho thiết bị tự kết nối lại | Đến khi ghép đôi lại/gỡ cài đặt; ACL SYSTEM/Administrators | Agent và quản trị viên Windows |
| Mã ghép đôi, trẻ/phụ huynh liên quan, thời điểm dùng | Ghép máy theo sự đồng ý của phụ huynh và kiểm toán | Mã dùng được 10 phút; lịch sử tối đa 90 ngày | Phụ huynh tạo mã; server |
| Quota, lịch tuần, danh sách app/domain | Thực thi quy tắc gia đình | Bản hiện hành đến khi thay/xóa hồ sơ; phiên bản/log tối đa 90 ngày | Trẻ trên màn hình minh bạch; phụ huynh |
| `screen_time` delta | Biểu đồ theo ngày/tuần từ bộ đếm thời gian hoạt động thực | 90 ngày | Trẻ và phụ huynh có quyền |
| Tên tiến trình trong `app_start/app_stop/blocked_app` | Minh bạch ứng dụng đã mở và giải thích việc chặn | 90 ngày | Trẻ và phụ huynh có quyền |
| Tên miền trong `domain_query/blocked_domain` | Phân loại truy vấn và giải thích việc chặn; không suy đoán thời lượng duyệt web | 90 ngày | Trẻ và phụ huynh có quyền |
| Yêu cầu xin thêm giờ, lý do, trạng thái | Cho trẻ trao đổi và phụ huynh phê duyệt | 90 ngày | Trẻ gửi yêu cầu; phụ huynh có quyền |
| Lệnh khóa/mở khóa/cấp giờ và ACK | Giao lệnh tin cậy và chẩn đoán | 90 ngày | Phụ huynh có quyền; server/Agent thực thi |
| Audit: tác nhân, hành động, thời điểm, thay đổi | Chứng minh đồng ý và truy vết thay đổi bảo vệ | 90 ngày | Phụ huynh có quyền; quản trị viên khi điều tra sự cố |
| IP trong log hạ tầng web (nếu reverse proxy bật) | Chống tấn công và chẩn đoán kết nối | Theo cấu hình hạ tầng, khuyến nghị tối đa 30 ngày | Quản trị viên hệ thống |
| SQLite Agent: policy cache, quota, event chưa gửi | Hoạt động khi mất mạng và đồng bộ lại không trùng | Policy/quota hiện tại; event xóa sau ACK hoặc khi gỡ | Agent; Administrators/SYSTEM |

Không thu thập nội dung phím gõ, nội dung tin nhắn, mật khẩu website, ảnh màn hình, webcam, micro, nội dung file hay lịch sử URL đầy đủ. Các trường không có mục đích trong bảng này không được thêm vào lược đồ.

