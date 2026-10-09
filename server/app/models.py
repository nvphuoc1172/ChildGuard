"""Models SQLAlchemy — tương ứng mục 4 (Mô hình dữ liệu) trong
docs/ChildGuard-Design.md. Phiên bản này chỉ chứa các bảng cần cho tính
năng Ghép đôi (enrollment); Event/Command sẽ thêm khi làm tính năng
Heartbeat.
"""
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)

from app.database import Base


def _new_id() -> str:
    return uuid.uuid4().hex


class Parent(Base):
    __tablename__ = "parents"

    id = Column(String(32), primary_key=True, default=_new_id)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True, default="Phụ huynh")
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Child(Base):
    __tablename__ = "children"

    id = Column(String(32), primary_key=True, default=_new_id)
    parent_id = Column(String(32), ForeignKey("parents.id"), nullable=False, index=True)
    display_name = Column(String(255), nullable=False)
    gender = Column(String(10), nullable=True, default="other")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Device(Base):
    __tablename__ = "devices"

    id = Column(String(32), primary_key=True, default=_new_id)
    child_id = Column(String(32), ForeignKey("children.id"), nullable=False, index=True)
    device_name = Column(String(100), nullable=True, default="Máy tính của trẻ")
    # Băm của (Machine GUID + hostname) sinh TẠI AGENT — xem mục 5.1 trong
    # Design.md. Server không bao giờ nhận dữ liệu định danh thô.
    fingerprint_hash = Column(String(64), nullable=False)
    enrolled_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String(20), default="active", nullable=False)  # active | revoked


class EnrollmentCode(Base):
    __tablename__ = "enrollment_codes"

    code = Column(String(8), primary_key=True)
    parent_id = Column(String(32), ForeignKey("parents.id"), nullable=False)
    child_id = Column(String(32), ForeignKey("children.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)


class Token(Base):
    __tablename__ = "tokens"

    id = Column(String(32), primary_key=True, default=_new_id)
    device_id = Column(String(32), ForeignKey("devices.id"), nullable=False, index=True)
    access_token_hash = Column(String(64), nullable=False)
    refresh_token_hash = Column(String(64), nullable=False)
    access_expires_at = Column(DateTime, nullable=False)
    refresh_expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)


class Policy(Base):
    __tablename__ = "policies"

    id = Column(String(32), primary_key=True, default=_new_id)
    child_id = Column(String(32), ForeignKey("children.id"), nullable=False, index=True)
    version = Column(Integer, nullable=False)
    # Lưu dạng JSON-as-text để tránh phụ thuộc JSON1 extension của SQLite.
    quota_json = Column(Text, nullable=False)
    schedule_json = Column(Text, nullable=False)
    app_rules_json = Column(Text, nullable=False)
    domain_rules_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Command(Base):
    __tablename__ = "commands"

    id = Column(String(32), primary_key=True, default=_new_id)
    device_id = Column(String(32), ForeignKey("devices.id"), nullable=False, index=True)
    command_type = Column(String(30), nullable=False)  # lock | unlock | grant_minutes
    payload_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    # delivered_at: NULL = agent chưa nhận được (đang chờ heartbeat/WS tiếp theo)
    delivered_at = Column(DateTime, nullable=True)
    acked_at = Column(DateTime, nullable=True)


class EventLog(Base):
    __tablename__ = "event_logs"

    id = Column(String(32), primary_key=True, default=_new_id)
    # Idempotency key sinh tại agent (hash của device_id + local_event_id)
    idempotency_key = Column(String(64), unique=True, index=True, nullable=False)
    device_id = Column(String(32), ForeignKey("devices.id"), nullable=False, index=True)
    child_id = Column(String(32), ForeignKey("children.id"), nullable=False, index=True)
    event_type = Column(String(50), nullable=False)  # screen_time | app_blocked | web_blocked | degraded_mode
    subject = Column(String(255), nullable=True)  # Tên process (app) hoặc domain (web) bị chặn
    duration_sec = Column(Integer, default=0, nullable=False)
    policy_version = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ChildRequest(Base):
    __tablename__ = "child_requests"

    id = Column(String(32), primary_key=True, default=_new_id)
    child_id = Column(String(32), ForeignKey("children.id"), nullable=False, index=True)
    device_id = Column(String(32), ForeignKey("devices.id"), nullable=False, index=True)
    request_type = Column(String(50), nullable=False)  # grant_time | unblock_app | unblock_web
    subject = Column(String(255), nullable=True)  # ví dụ "15" (phút), hoặc tên app/domain
    reason = Column(Text, nullable=True)
    status = Column(String(20), default="pending", nullable=False)  # pending | approved | rejected
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(32), primary_key=True, default=_new_id)
    actor_type = Column(String(20), nullable=False)  # parent | agent | system
    actor_id = Column(String(32), nullable=True)
    action = Column(String(100), nullable=False)
    detail_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)