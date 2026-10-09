"""Kênh điều khiển & lệnh khẩn cấp (Commands + WebSocket) — xem mục 5.3 trong Design.md.

Hỗ trợ:
- POST /commands: Phụ huynh hoặc Dashboard phát lệnh khẩn cấp (lock/unlock/grant_minutes).
  Độ trễ < 5 giây nếu Agent đang kết nối WebSocket!
- POST /commands/{id}/ack: Agent xác nhận đã thực thi lệnh.
- WS /ws/{device_id}: Kênh WebSocket thời gian thực cho Agent.
"""
import json
from datetime import datetime
from typing import Dict, List

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from sqlalchemy.orm import Session

from app import models, schemas, security
from app.database import SessionLocal, get_db
from app.deps import get_current_device

router = APIRouter(tags=["commands"])


class ConnectionManager:
    """Quản lý các kết nối WebSocket thời gian thực tới các Agent."""

    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, device_id: str, websocket: WebSocket):
        await websocket.accept()
        if device_id not in self.active_connections:
            self.active_connections[device_id] = []
        self.active_connections[device_id].append(websocket)

    def disconnect(self, device_id: str, websocket: WebSocket):
        if device_id in self.active_connections:
            if websocket in self.active_connections[device_id]:
                self.active_connections[device_id].remove(websocket)
            if not self.active_connections[device_id]:
                del self.active_connections[device_id]

    async def send_command(self, device_id: str, command_data: dict) -> bool:
        """Gửi lệnh tức thì qua WebSocket tới Agent nếu đang kết nối."""
        sockets = self.active_connections.get(device_id, [])
        delivered = False
        for ws in list(sockets):
            try:
                await ws.send_json(command_data)
                delivered = True
            except Exception:
                self.disconnect(device_id, ws)
        return delivered


manager = ConnectionManager()


@router.post("/commands", response_model=schemas.PendingCommandOut, status_code=status.HTTP_201_CREATED)
async def create_command(
    payload: schemas.CommandCreateRequest,
    db: Session = Depends(get_db),
):
    """Phụ huynh/Dashboard tạo lệnh khẩn cấp cho một thiết bị."""
    device = db.get(models.Device, payload.device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="device_not_found")

    if payload.command_type not in ("lock", "unlock", "grant_minutes"):
        raise HTTPException(status_code=400, detail="invalid_command_type")

    now = datetime.utcnow()
    cmd = models.Command(
        device_id=device.id,
        command_type=payload.command_type,
        payload_json=json.dumps(payload.payload),
        created_at=now,
    )
    db.add(cmd)
    db.flush()

    # Thử đẩy ngay qua WebSocket (<5s độ trễ)
    cmd_data = {
        "command_id": cmd.id,
        "type": cmd.command_type,
        "payload": payload.payload,
    }
    sent = await manager.send_command(device.id, cmd_data)
    if sent:
        cmd.delivered_at = now

    db.commit()
    db.refresh(cmd)

    return schemas.PendingCommandOut(
        command_id=cmd.id,
        type=cmd.command_type,
        payload=payload.payload,
    )


@router.post("/commands/{command_id}/ack")
def ack_command(
    command_id: str,
    ack: schemas.CommandAckRequest = None,
    device: models.Device = Depends(get_current_device),
    db: Session = Depends(get_db),
):
    """Agent xác nhận đã thực thi thành công một lệnh."""
    cmd = db.get(models.Command, command_id)
    if cmd is None:
        raise HTTPException(status_code=404, detail="command_not_found")

    if cmd.device_id != device.id:
        raise HTTPException(status_code=403, detail="command_not_for_this_device")

    now = datetime.utcnow()
    if cmd.delivered_at is None:
        cmd.delivered_at = now
    cmd.acked_at = now
    db.commit()

    return {"status": "ok", "command_id": command_id, "acked_at": cmd.acked_at.isoformat()}


@router.websocket("/ws/{device_id}")
async def websocket_device_endpoint(
    websocket: WebSocket,
    device_id: str,
    token: str = Query(default=""),
):
    """Kênh WebSocket hai chiều cho Agent nhận lệnh khẩn cấp và gửi ACK tức thì."""
    # Xác thực token của thiết bị
    db = SessionLocal()
    try:
        raw_token = token
        if not raw_token:
            # Thử lấy từ header
            auth_h = websocket.headers.get("authorization", "")
            if auth_h.startswith("Bearer "):
                raw_token = auth_h.removeprefix("Bearer ").strip()

        if not raw_token:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        token_hash = security.hash_token(raw_token)
        token_row = (
            db.query(models.Token)
            .filter(models.Token.access_token_hash == token_hash)
            .first()
        )
        if (
            token_row is None
            or token_row.revoked
            or token_row.access_expires_at < datetime.utcnow()
            or token_row.device_id != device_id
        ):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        device = db.get(models.Device, device_id)
        if device is None or device.status != "active":
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        # Cập nhật last_seen_at
        device.last_seen_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()

    await manager.connect(device_id, websocket)

    try:
        # Kiểm tra xem có lệnh pending nào chưa giao không -> giao ngay
        db = SessionLocal()
        try:
            pending = (
                db.query(models.Command)
                .filter(models.Command.device_id == device_id, models.Command.delivered_at.is_(None))
                .order_by(models.Command.created_at.asc())
                .all()
            )
            now = datetime.utcnow()
            for cmd in pending:
                await websocket.send_json(
                    {
                        "command_id": cmd.id,
                        "type": cmd.command_type,
                        "payload": json.loads(cmd.payload_json),
                    }
                )
                cmd.delivered_at = now
            db.commit()
        finally:
            db.close()

        # Vòng lặp nhận ACK hoặc Ping từ Agent
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ack" and "command_id" in msg:
                    db = SessionLocal()
                    try:
                        cmd = db.get(models.Command, msg["command_id"])
                        if cmd and cmd.device_id == device_id:
                            cmd.acked_at = datetime.utcnow()
                            db.commit()
                    finally:
                        db.close()
                elif msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(device_id, websocket)
