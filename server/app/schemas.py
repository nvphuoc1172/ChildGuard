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