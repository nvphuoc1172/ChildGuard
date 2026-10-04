from pydantic import BaseModel, Field


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
