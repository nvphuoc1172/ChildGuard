"""OGK-Agent — Tray UI (Giao diện người dùng cho trẻ em) — xem mục 3 trong Design.md.

Chạy trong phiên người dùng (user session):
- Hiển thị biểu tượng ở khay hệ thống (System Tray).
- Cập nhật thời gian còn lại (đếm ngược).
- Màn hình minh bạch: Xem chính sách mà phụ huynh đã đặt (giờ giấc, app cấm, web cấm).
- Nút "Xin thêm giờ": Gửi yêu cầu qua IPC lên Server để phụ huynh phê duyệt.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
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
        # Vẽ một biểu tượng khiên bảo vệ đơn giản 64x64
        img = Image.new("RGBA", (64, 64), color=(0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        # Vẽ hình khiên màu xanh dương
        d.polygon([(32, 4), (60, 16), (60, 44), (32, 60), (4, 44), (4, 16)], fill=(59, 130, 246, 255))
        d.polygon([(32, 8), (56, 18), (56, 42), (32, 56), (8, 42), (8, 18)], fill=(30, 41, 59, 255))
        d.ellipse([(24, 24), (40, 40)], fill=(16, 185, 129, 255))
        return img

    def show_transparency_window(self):
        """Màn hình minh bạch: cho trẻ xem toàn bộ chính sách đang áp dụng."""
        if not tk:
            return

        def _open():
            root = tk.Tk()
            root.title("ChildGuard — Chính sách bảo vệ của gia đình")
            root.geometry("480x420")
            root.configure(bg="#0f172a")

            status = self.fetch_status()
            policy = status.get("policy", {})
            quota = policy.get("quota", {})
            schedule = policy.get("schedule", {})
            app_rules = policy.get("app_rules", {})
            domain_rules = policy.get("domain_rules", {})

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

            info_text = (
                f"⏱️ Hạn mức mỗi ngày: {quota.get('daily_minutes', 120)} phút\n"
                f"⏳ Đã sử dụng hôm nay: {status.get('used_minutes', 0)} phút\n"
                f"🟢 Thời gian còn lại: {status.get('remaining_minutes', 0)} phút\n\n"
                f"📅 Khung giờ cho phép: {schedule.get('start_time', '07:00')} đến {schedule.get('end_time', '21:30')}\n\n"
                f"🚫 Ứng dụng bị hạn chế:\n"
                f"  {', '.join(app_rules.get('blacklist', [])) or 'Không có'}\n\n"
                f"🌐 Website bị hạn chế:\n"
                f"  {', '.join(domain_rules.get('blacklist', [])) or 'Không có'}\n"
            )

            msg = tk.Label(frame, text=info_text, justify="left", fg="#f8fafc", bg="#1e293b", font=("Segoe UI", 11))
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

    def run(self):
        if not pystray:
            print("[Tray] Thư viện pystray chưa được cài đặt. Tray UI chạy ở chế độ fallback.")
            while self.running:
                time.sleep(1)
            return

        image = self.create_tray_image()

        def _get_time_label(item):
            st = self.fetch_status()
            rem = st.get("remaining_minutes", "—")
            return f"⏳ Còn lại: {rem} phút"

        menu = pystray.Menu(
            pystray.MenuItem(_get_time_label, None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("📋 Xem chính sách bảo vệ", lambda: self.show_transparency_window()),
            pystray.MenuItem("🙋 Xin thêm giờ...", lambda: self.show_request_window()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Thoát", lambda: self.stop()),
        )

        self.icon = pystray.Icon("ChildGuard", image, "ChildGuard — Đang bảo vệ", menu)
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
