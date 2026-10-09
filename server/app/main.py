"""Điểm khởi chạy OGK-Server.

Chạy dev: uvicorn app.main:app --reload --port 8000 (HTTP, trên máy dev)
Chạy thật trên VM: xem lệnh uvicorn với --ssl-keyfile/--ssl-certfile
trong docs/SETUP_ENVIRONMENT.md, mục A11.
"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.database import Base, auto_migrate, engine
from app.routers import (
    auth,
    commands,
    dashboard,
    enroll,
    events,
    heartbeat,
    policy,
    reports,
    requests,
)

# server/app/main.py -> ... -> ChildGuard/dashboard/
DASHBOARD_DIR = Path(__file__).resolve().parent.parent.parent / "dashboard"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Dev-only: tạo bảng trực tiếp từ models. Khi dự án lớn hơn, thay bằng
    # Alembic migrations (thư mục server/migrations/ đã có trong cấu trúc).
    Base.metadata.create_all(bind=engine)
    auto_migrate(engine)
    yield



app = FastAPI(title="OGK-Server", version="0.1.0", lifespan=lifespan)

app.include_router(auth.router)
app.include_router(enroll.router)
app.include_router(heartbeat.router)
app.include_router(commands.router)
app.include_router(events.router)
app.include_router(policy.router)
app.include_router(requests.router)
app.include_router(reports.router)
app.include_router(dashboard.router)


app.mount(
    "/static",
    StaticFiles(directory=str(DASHBOARD_DIR / "static")),
    name="static",
)


@app.get("/ping")
def ping():
    """Dùng để smoke-test — thay cho /tmp/hello.py tạm thời trước đó."""
    return {"status": "ok", "service": "ogk-server"}