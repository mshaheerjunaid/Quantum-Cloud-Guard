"""API request/response schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SetupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=8, max_length=256)


class LoginRequest(BaseModel):
    username: str
    password: str
    otp: str | None = None


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=8, max_length=256)


class ForgotPasswordRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)


class ChangePasswordRequest(BaseModel):
    current_password: str | None = None
    new_password: str = Field(min_length=8, max_length=256)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=8, max_length=256)
    is_admin: bool = False
    role: str = Field(default="engineer", max_length=32)


class CheckoutRequest(BaseModel):
    wrapped: dict


class CheckinRequest(BaseModel):
    lease_id: str = Field(min_length=1, max_length=128)


class RoleUpdateRequest(BaseModel):
    role: str = Field(min_length=1, max_length=32)


class GenerateKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class GrantRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)


class EncryptRequest(BaseModel):
    key: str = Field(min_length=1, max_length=128)
    plaintext: str
    aad: str | None = None


class DecryptRequest(BaseModel):
    envelope: dict
    aad: str | None = None


class DecryptResponse(BaseModel):
    plaintext: str
    timing_ms: float | None = None


class DataKeyRequest(BaseModel):
    key: str = Field(min_length=1, max_length=128)


class UnwrapRequest(BaseModel):
    wrapped: dict


class MfaActivateRequest(BaseModel):
    otp: str = Field(min_length=6, max_length=10)


class ApiKeyCreateRequest(BaseModel):
    label: str = Field(min_length=1, max_length=64)
    owner: str | None = None
