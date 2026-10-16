"""OGK-Agent — Tray UI (Giao diện người dùng cho trẻ em) — xem mục 3 trong Design.md.

Chạy trong phiên người dùng (user session):
- Hiển thị biểu tượng ở khay hệ thống (System Tray).
- Cập nhật thời gian còn lại (đếm ngược thời gian thực mỗi 2 giây).
- Màn hình minh bạch: Xem chính sách mà phụ huynh đã đặt (tự động cập nhật thời gian thực).
- Nút "Xin thêm giờ": Gửi yêu cầu qua IPC lên Server để phụ huynh phê duyệt.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from datetime import datetime
from typing import Optional

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except ImportError:
    tk = None

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    pystray = None


class TrayApp:
    def __init__(self, ipc_url: str = "http://127.0.0.1:48123"):
        self.ipc_url = ipc_url
        self.icon = None
        self.status = {}
        self.running = True

    def fetch_status(self) -> dict:
        try:
            req = urllib.request.Request(f"{self.ipc_url}/status", headers={"User-Agent": "ChildGuard-Tray"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                self.status = json.loads(resp.read().decode("utf-8"))
                return self.status
        except Exception:
            return {}

    def send_request(self, minutes: int, reason: str) -> bool:
        try:
            body = json.dumps({"minutes": minutes, "reason": reason}).encode("utf-8")
            req = urllib.request.Request(
                f"{self.ipc_url}/request",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def create_tray_image(self, text: str = "🛡️"):
        img = Image.new("RGBA", (64, 64), color=(0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.polygon([(32, 4), (60, 16), (60, 44), (32, 60), (4, 44), (4, 16)], fill=(59, 130, 246, 255))
        d.polygon([(32, 8), (56, 18), (56, 42), (32, 56), (8, 42), (8, 18)], fill=(30, 41, 59, 255))
        d.ellipse([(24, 24), (40, 40)], fill=(16, 185, 129, 255))
        return img

    def show_transparency_window(self):
        """Màn hình minh bạch: cho trẻ xem toàn bộ chính sách và đếm thời gian thực."""
        if not tk:
            return

        def _open():
            root = tk.Tk()
            root.title("ChildGuard — Chính sách bảo vệ của gia đình")
            root.geometry("480x430")
            root.configure(bg="#0f172a")

            title_lbl = tk.Label(
                root,
                text="🛡️ Quy định sử dụng máy tính",
                font=("Segoe UI", 16, "bold"),
                fg="#f8fafc",
                bg="#0f172a",
            )
            title_lbl.pack(pady=12)

            sub_lbl = tk.Label(
                root,
                text="Phần mềm hoạt động minh bạch theo thoả thuận với cha mẹ.",
                font=("Segoe UI", 10),
                fg="#94a3b8",
                bg="#0f172a",
            )
            sub_lbl.pack()

            frame = tk.Frame(root, bg="#1e293b", padx=16, pady=16)
            frame.pack(fill="both", expand=True, padx=16, pady=16)

            info_var = tk.StringVar()

            def _update_info():
                if not root.winfo_exists():
                    return
                st = self.fetch_status()
                pol = st.get("policy", {})
                q = pol.get("quota", {})
                sch = pol.get("schedule", {})
                ar = pol.get("app_rules", {})
                dr = pol.get("domain_rules", {})

                d_quota = q.get("daily_minutes", st.get("daily_quota", 120))
                u_min = st.get("used_minutes", 0)
                r_min = st.get("remaining_minutes", 0)
                is_locked = st.get("is_locked", False)
                is_idle = st.get("is_idle", False)
                if is_locked:
                    lock_tag = " (🔒 Đang khóa)"
                elif is_idle:
                    lock_tag = " (💤 Tạm dừng - Không thao tác >5p)"
                else:
                    lock_tag = " (🟢 Đang dùng)"

                matrix = sch.get("matrix")
                if matrix and isinstance(matrix, list) and len(matrix) == 7:
                    now_dt = datetime.now()
                    day = now_dt.weekday()
                    slot = now_dt.hour * 2 + (now_dt.minute // 30)
                    slot_allowed = bool(matrix[day][slot]) if (0 <= day < 7 and 0 <= slot < 48) else True
                    status_text = "🟢 Trong giờ cho phép" if slot_allowed else "🔒 Ngoài khung giờ (Khóa trong 5s)"
                    schedule_text = f"📅 Lịch tuần 7x48: {status_text}\n"
                else:
                    schedule_text = f"📅 Khung giờ cho phép: {sch.get('start_time', '07:00')} đến {sch.get('end_time', '21:30')}\n"

                if isinstance(ar, list):
                    app_items = ar
                    app_label = "🚫 Ứng dụng bị cấm (Blacklist):"
                elif isinstance(ar, dict) and ar.get("mode") == "whitelist":
                    app_items = ar.get("whitelist", [])
                    app_label = "✅ Chỉ cho phép (Whitelist):"
                elif isinstance(ar, dict):
                    app_items = ar.get("blacklist", [])
                    app_label = "🚫 Ứng dụng bị cấm (Blacklist):"
                else:
                    app_items = []
                    app_label = "🚫 Ứng dụng bị cấm (Blacklist):"

                app_display_list = []
                for it in app_items:
                    if isinstance(it, dict):
                        app_display_list.append(it.get("name") or it.get("sha256") or str(it))
                    else:
                        app_display_list.append(str(it))

                info_var.set(
                    f"⏱️ Hạn mức mỗi ngày: {d_quota} phút\n"
                    f"⏳ Đã sử dụng hôm nay: {u_min} phút\n"
                    f"🟢 Thời gian còn lại: {r_min} phút{lock_tag}\n\n"
                    f"{schedule_text}\n"
                    f"{app_label}\n"
                    f"  {', '.join(app_display_list) or 'Không có'}\n\n"
                    f"🌐 Website bị hạn chế:\n"
                    f"  {', '.join(dr.get('blacklist', [])) or 'Không có'}\n"
                )
                root.after(2000, _update_info)

            _update_info()

            msg = tk.Label(frame, textvariable=info_var, justify="left", fg="#f8fafc", bg="#1e293b", font=("Segoe UI", 11))
            msg.pack(anchor="w")

            btn_close = tk.Button(
                root,
                text="Đóng",
                command=root.destroy,
                bg="#3b82f6",
                fg="white",
                font=("Segoe UI", 10, "bold"),
                padx=16,
                pady=6,
                relief="flat",
            )
            btn_close.pack(pady=8)
            root.mainloop()

        threading.Thread(target=_open, daemon=True).start()

    def show_request_window(self):
        """Cửa sổ xin thêm giờ sử dụng."""
        if not tk:
            return

        def _open():
            root = tk.Tk()
            root.title("Xin thêm giờ sử dụng máy")
            root.geometry("400x320")
            root.configure(bg="#0f172a")

            tk.Label(
                root,
                text="🙋 Xin thêm thời gian",
                font=("Segoe UI", 15, "bold"),
                fg="#f8fafc",
                bg="#0f172a",
            ).pack(pady=12)

            tk.Label(
                root,
                text="Chọn số phút muốn xin thêm:",
                font=("Segoe UI", 10),
                fg="#94a3b8",
                bg="#0f172a",
            ).pack(anchor="w", padx=24)

            minutes_var = tk.IntVar(value=15)
            btn_frame = tk.Frame(root, bg="#0f172a")
            btn_frame.pack(fill="x", padx=24, pady=8)

            for mins in (15, 30, 60):
                tk.Radiobutton(
                    btn_frame,
                    text=f"+{mins} phút",
                    variable=minutes_var,
                    value=mins,
                    fg="#f8fafc",
                    bg="#0f172a",
                    selectcolor="#1e293b",
                    font=("Segoe UI", 11),
                ).pack(side="left", padx=10)

            # Ô nhập số phút tùy chỉnh
            tk.Radiobutton(
                btn_frame,
                text="Khác:",
                variable=minutes_var,
                value=0, # Giá trị 0 đánh dấu là dùng ô nhập tay
                fg="#f8fafc",
                bg="#0f172a",
                selectcolor="#1e293b",
                font=("Segoe UI", 11),
            ).pack(side="left", padx=(10, 2))
            
            custom_min_entry = tk.Entry(btn_frame, font=("Segoe UI", 11), bg="#1e293b", fg="#f8fafc", width=5, insertbackground="white")
            custom_min_entry.pack(side="left", padx=2)
            custom_min_entry.insert(0, "90")
            
            tk.Label(
                root,
                text="Lý do xin thêm (để phụ huynh duyệt):",
                font=("Segoe UI", 10),
                fg="#94a3b8",
                bg="#0f172a",
            ).pack(anchor="w", padx=24, pady=(8, 4))

            reason_entry = tk.Entry(root, font=("Segoe UI", 11), bg="#1e293b", fg="#f8fafc", insertbackground="white")
            reason_entry.pack(fill="x", padx=24, pady=4)

            def _submit():
                mins = minutes_var.get()

                if mins == 0:  # Trẻ chọn ô "Khác"
                    try:
                        mins = int(custom_min_entry.get().strip())
                    except ValueError:
                        messagebox.showwarning("Lỗi", "Vui lòng nhập số phút hợp lệ!")
                        return
                    
                reason = reason_entry.get().strip()
                ok = self.send_request(mins, reason)
                if ok:
                    messagebox.showinfo("Thành công", f"Đã gửi yêu cầu xin thêm {mins} phút tới cha mẹ. Hãy đợi cha mẹ phê duyệt nhé!")
                    root.destroy()
                else:
                    messagebox.showerror("Lỗi", "Không kết nối được tới dịch vụ ChildGuard để gửi yêu cầu.")

            tk.Button(
                root,
                text="Gửi yêu cầu tới cha mẹ",
                command=_submit,
                bg="#10b981",
                fg="white",
                font=("Segoe UI", 11, "bold"),
                padx=16,
                pady=8,
                relief="flat",
            ).pack(pady=18)

            root.mainloop()

        threading.Thread(target=_open, daemon=True).start()

    def show_toast_banner(self, notif: dict):
        """Hiển thị cửa sổ banner thông báo nổi bật trên màn hình cho trẻ."""
        if not tk:
            return

        def _popup():
            try:
                root = tk.Tk()
                root.overrideredirect(True)
                root.attributes("-topmost", True)
                bg_color = "#b91c1c" if notif.get("level") == "grace_period" else ("#ea580c" if notif.get("level") == "urgent" else "#1e293b")
                root.configure(bg=bg_color)

                sw = root.winfo_screenwidth()
                sh = root.winfo_screenheight()
                w, h = 420, 130
                root.geometry(f"{w}x{h}+{sw - w - 24}+{sh - h - 60}")

                frame = tk.Frame(root, bg=bg_color, padx=14, pady=12)
                frame.pack(fill="both", expand=True)

                title_lbl = tk.Label(frame, text=notif.get("title", "ChildGuard"), font=("Segoe UI", 12, "bold"), fg="white", bg=bg_color)
                title_lbl.pack(anchor="w")

                msg_lbl = tk.Label(frame, text=notif.get("message", ""), font=("Segoe UI", 10), fg="#f1f5f9", bg=bg_color, wraplength=380, justify="left")
                msg_lbl.pack(anchor="w", pady=4)

                btn_close = tk.Button(frame, text="Đã hiểu / Lưu bài", font=("Segoe UI", 9, "bold"), bg="#0f172a", fg="white", padx=10, pady=2, relief="flat", command=root.destroy)
                btn_close.pack(anchor="e")

                root.after(10000, lambda: root.destroy() if root.winfo_exists() else None)
                root.mainloop()
            except Exception:
                pass

        threading.Thread(target=_popup, daemon=True).start()

    def run(self):
        if not pystray:
            print("[Tray] Thư viện pystray chưa được cài đặt. Tray UI chạy ở chế độ fallback.")
            while self.running:
                time.sleep(1)
            return

        image = self.create_tray_image()

        def _get_time_text():
            st = self.fetch_status()
            rem = st.get("remaining_minutes", 0)
            quota = st.get("daily_quota", 0)
            used = st.get("used_minutes", 0)
            is_locked = st.get("is_locked", False)
            is_idle = st.get("is_idle", False)
            in_grace = st.get("in_grace_period", False)
            grace_left = st.get("grace_seconds_left", 0)

            if in_grace:
                return f"⚠️ Ân hạn lưu bài: Còn {grace_left} giây!"
            if is_locked or rem <= 0:
                return f"🔒 Đã khóa (Còn lại: 0/{quota} phút)"
            if is_idle:
                return f"💤 Tạm dừng (>5p không thao tác) - Còn lại: {rem}/{quota}p"
            return f"⏳ Còn lại: {rem} / {quota} phút (Đã dùng: {used}p)"

        def _build_menu():
            return pystray.Menu(
                pystray.MenuItem(_get_time_text(), None, enabled=False),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("📋 Xem chính sách bảo vệ", lambda: self.show_transparency_window()),
                pystray.MenuItem("🙋 Xin thêm giờ...", lambda: self.show_request_window()),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Thoát", lambda: self.stop()),
            )

        self.icon = pystray.Icon("ChildGuard", image, "ChildGuard — Đang bảo vệ", _build_menu())

        # Vòng lặp nền cập nhật trực tiếp tooltip và menu mỗi 2 giây
        def _updater():
            while self.running:
                time.sleep(2)
                if self.icon and getattr(self.icon, "visible", False):
                    try:
                        st = self.fetch_status()
                        rem = st.get("remaining_minutes", 0)
                        quota = st.get("daily_quota", 0)
                        is_locked = st.get("is_locked", False)
                        is_idle = st.get("is_idle", False)
                        in_grace = st.get("in_grace_period", False)
                        grace_left = st.get("grace_seconds_left", 0)

                        if in_grace:
                            status_str = f"Ân hạn {grace_left}s"
                        elif is_locked or rem <= 0:
                            status_str = "Đã khóa"
                        elif is_idle:
                            status_str = "Tạm dừng"
                        else:
                            status_str = f"Còn {rem}p"
                        self.icon.title = f"ChildGuard — {status_str} ({rem}/{quota} phút)"
                        self.icon.menu = _build_menu()
                        self.icon.update_menu()

                        # Xử lý hiển thị thông báo mới
                        notif = st.get("active_notification")
                        if notif and notif.get("id") != getattr(self, "_last_notif_id", None):
                            self._last_notif_id = notif.get("id")
                            msg = notif.get("message", "")
                            title = notif.get("title", "ChildGuard")
                            try:
                                self.icon.notify(msg, title)
                            except Exception:
                                pass
                            self.show_toast_banner(notif)
                    except Exception:
                        pass

        threading.Thread(target=_updater, daemon=True).start()
        print("[Tray] Đã khởi chạy biểu tượng khay hệ thống (System Tray).")
        self.icon.run()

    def stop(self):
        self.running = False
        if self.icon:
            self.icon.stop()


def main():
    app = TrayApp()
    app.run()


if __name__ == "__main__":
    main()
