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
