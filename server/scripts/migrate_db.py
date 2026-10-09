"""Script nâng cấp schema database SQLite khi có thêm cột mới.

Chạy trên VM:
    cd /opt/childguard/app/server
    python -m scripts.migrate_db

Script này an toàn để chạy nhiều lần, không làm mất dữ liệu đã có.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import Base, auto_migrate, engine


def main():
    print("Đang kiểm tra và nâng cấp bảng dữ liệu SQLite...")
    Base.metadata.create_all(bind=engine)
    auto_migrate(engine)
    print("✓ Đã hoàn tất nâng cấp schema thành công! Mọi cột còn thiếu đã được thêm vào.")


if __name__ == "__main__":
    main()
