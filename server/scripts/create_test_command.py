"""Tạo một lệnh thử nghiệm cho một thiết bị cụ thể — thay tạm cho nút
"Khoá ngay"/"Cộng giờ" trên dashboard (dashboard chưa có nút điều khiển
thật, chỉ mới có trang xem trạng thái read-only).

Dùng để kiểm tra: agent/heartbeat.py có nhận được lệnh ở lần heartbeat
kế tiếp hay không (tối đa {interval}s sau khi script này chạy).

Chạy trên VM:
    cd /opt/childguard/app/server
    python -m scripts.create_test_command --device-id <id> --type grant_minutes --minutes 15
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import models  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--type", required=True, choices=["lock", "unlock", "grant_minutes"])
    parser.add_argument("--minutes", type=int, default=15, help="Chỉ dùng khi --type grant_minutes")
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        device = db.get(models.Device, args.device_id)
        if device is None:
            raise SystemExit(
                f"Không tìm thấy device_id={args.device_id}. "
                "Xem danh sách tại http://<server>:8443/dashboard/devices"
            )

        payload = {"minutes": args.minutes} if args.type == "grant_minutes" else {}
        command = models.Command(
            device_id=device.id,
            command_type=args.type,
            payload_json=json.dumps(payload),
        )
        db.add(command)
        db.commit()

        print(f"Đã tạo lệnh '{args.type}' cho device {device.id} (command_id={command.id})")
        print("Lệnh sẽ được giao ở lần heartbeat tiếp theo của agent.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
