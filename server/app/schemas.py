from pydantic import BaseModel, Field


class HeartbeatRequest(BaseModel):
    policy_version: int = Field(..., ge=0)
    quota_used_seconds: int = Field(..., ge=0)
    queued_event_count: int = Field(..., ge=0)


class PendingCommandOut(BaseModel):
    command_id: str
    type: str
    payload: dict


class HeartbeatResponse(BaseModel):
    policy_version: int
    policy_changed: bool
    pending_commands: list[PendingCommandOut]


class PolicyOut(BaseModel):
    version: int
    quota: dict
    schedule: dict
    app_rules: dict
    domain_rules: dict


class EnrollRequest(BaseModel):
    code: str = Field(..., min_length=8, max_length=8)
    device_fingerprint: str = Field(..., min_length=16, max_length=128)


class EnrollResponse(BaseModel):
    device_id: str
    access_token: str
    refresh_token: str
    policy_version: int


class ErrorResponse(BaseModel):
    detail: str


# --- Commands Schemas ---
class CommandCreateRequest(BaseModel):
    device_id: str
    command_type: str = Field(..., description="lock | unlock | grant_minutes")
    payload: dict = Field(default_factory=dict)


class CommandOut(BaseModel):
    id: str
    device_id: str
    command_type: str
    payload: dict
    created_at: str
    delivered_at: str | None
    acked_at: str | None


class CommandAckRequest(BaseModel):
    status: str = Field(default="ok")


# --- Event Batch Schemas ---
class EventItem(BaseModel):
    idempotency_key: str = Field(..., min_length=8, max_length=64)
    event_type: str = Field(..., description="screen_time | app_blocked | web_blocked | degraded_mode")
    subject: str | None = None
    duration_sec: int = Field(default=0, ge=0)
    policy_version: int | None = None
    created_at: str | None = None


class BatchEventsRequest(BaseModel):
    events: list[EventItem]


class BatchEventsResponse(BaseModel):
    processed: int
    ignored: int


# --- Child Requests Schemas ---
class ChildRequestCreate(BaseModel):
    request_type: str = Field(default="grant_time", description="grant_time | unblock_app | unblock_web")
    subject: str | None = None  # e.g., "15" (minutes) or "game.exe"
    reason: str | None = None


class ChildRequestOut(BaseModel):
    id: str
    child_id: str
    device_id: str
    request_type: str
    subject: str | None
    reason: str | None
    status: str
    created_at: str
    resolved_at: str | None


class ChildRequestAction(BaseModel):
    action: str = Field(..., description="approve | reject")
    minutes: int | None = Field(default=15, description="Minutes to grant if approved")


# --- Policy Update Schema ---
class PolicyUpdateRequest(BaseModel):
    child_id: str
    quota: dict = Field(default_factory=lambda: {"daily_minutes": 120})
    schedule: dict = Field(default_factory=dict)
    app_rules: dict = Field(default_factory=lambda: {"mode": "allow_all"})
    domain_rules: dict = Field(default_factory=lambda: {"mode": "allow_all"})


# --- Auth Schemas ---
class ParentLoginRequest(BaseModel):
    email: str
    password: str


class ParentLoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    parent_email: str
    parent_name: str