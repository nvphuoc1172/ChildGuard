"""Điểm khởi chạy OGK-Server.

Chạy dev: uvicorn app.main:app --reload --port 8000 (HTTP, trên máy dev)
Chạy thật trên VM: xem lệnh uvicorn với --ssl-keyfile/--ssl-certfile
trong docs/SETUP_ENVIRONMENT.md, mục A11.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.database import Base, engine
from app.routers import enroll


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Dev-only: tạo bảng trực tiếp từ models. Khi dự án lớn hơn, thay bằng
    # Alembic migrations (thư mục server/migrations/ đã có trong cấu trúc).
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="OGK-Server", version="0.1.0", lifespan=lifespan)

app.include_router(enroll.router)


@app.get("/ping")
def ping():
    """Dùng để smoke-test — thay cho /tmp/hello.py tạm thời trước đó."""
    return {"status": "ok", "service": "ogk-server"}
