"""Thiết lập kết nối SQLAlchemy cho OGK-Server.

Dùng SQLite ở chế độ WAL (Write-Ahead Logging) để chịu được ghi đồng thời
ở quy mô lab — xem mục 9 trong docs/ChildGuard-Design.md.
"""
import os

from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

# Đường dẫn file DB — đổi qua biến môi trường OGK_DB_PATH khi deploy thật.
# Mặc định trỏ vào /opt/childguard/data/ogk.db (đúng cấu trúc đã dựng ở VM).
DB_PATH = os.environ.get("OGK_DB_PATH", "/opt/childguard/data/ogk.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)


@event.listens_for(engine, "connect")
def _enable_wal_mode(dbapi_connection, connection_record):
    """Bật WAL mode cho mỗi kết nối SQLite mới."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency: mở một session cho mỗi request, luôn đóng lại sau."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def auto_migrate(db_engine=engine):
    """Tự động kiểm tra và thêm các cột mới vào các bảng SQLite đã tồn tại trước đó,
    tránh lỗi 'no such column' khi nâng cấp schema mà không dùng Alembic.
    """
    with db_engine.connect() as conn:
        # 1. Bảng parents
        res = conn.exec_driver_sql("PRAGMA table_info(parents)")
        parent_cols = {row[1] for row in res.fetchall()}
        if parent_cols:
            if "full_name" not in parent_cols:
                conn.exec_driver_sql("ALTER TABLE parents ADD COLUMN full_name VARCHAR(255) DEFAULT 'Phụ huynh'")
            if "failed_login_attempts" not in parent_cols:
                conn.exec_driver_sql("ALTER TABLE parents ADD COLUMN failed_login_attempts INTEGER DEFAULT 0 NOT NULL")
            if "locked_until" not in parent_cols:
                conn.exec_driver_sql("ALTER TABLE parents ADD COLUMN locked_until DATETIME")

        # 2. Bảng children
        res = conn.exec_driver_sql("PRAGMA table_info(children)")
        child_cols = {row[1] for row in res.fetchall()}
        if child_cols:
            if "gender" not in child_cols:
                conn.exec_driver_sql("ALTER TABLE children ADD COLUMN gender VARCHAR(10) DEFAULT 'other'")

        # 3. Bảng devices
        res = conn.exec_driver_sql("PRAGMA table_info(devices)")
        dev_cols = {row[1] for row in res.fetchall()}
        if dev_cols:
            if "device_name" not in dev_cols:
                conn.exec_driver_sql("ALTER TABLE devices ADD COLUMN device_name VARCHAR(100) DEFAULT 'Máy tính của trẻ'")

        conn.commit()

