"""Fixture dùng chung cho test suite.

Mỗi test chạy trên một file SQLite tạm riêng (qua pytest's tmp_path),
không đụng tới DB thật ở /opt/childguard/data — an toàn để chạy nhiều
lần, kể cả song song.
"""
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

SERVER_DIR = Path(__file__).resolve().parent.parent / "server"
sys.path.insert(0, str(SERVER_DIR))

# app.database đọc OGK_DB_PATH ngay lúc import để tạo engine "mặc định"
# (dùng bởi FastAPI lifespan khi app khởi động). Trỏ nó vào một thư mục
# tạm cục bộ TRƯỚC khi import, để test chạy được trên mọi hệ điều hành —
# không phụ thuộc đường dẫn /opt/childguard chỉ tồn tại trên VM thật.
# Mỗi test vẫn dùng DB RIÊNG qua fixture db_session bên dưới, không đụng
# tới file này.
_TEST_DATA_DIR = Path(__file__).resolve().parent / ".tmp_server_data"
_TEST_DATA_DIR.mkdir(exist_ok=True)
os.environ.setdefault("OGK_DB_PATH", str(_TEST_DATA_DIR / "default_ogk.db"))

from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def db_session(tmp_path):
    db_file = tmp_path / "test_ogk.db"
    engine = create_engine(
        f"sqlite:///{db_file}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_session):
    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
