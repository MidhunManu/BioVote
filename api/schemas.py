from pydantic import (
  BaseModel,
  Field,
  EmailStr,
)


class DefaultModel(BaseModel):
  class Config:
    from_attributes = True


class LoginRequest(DefaultModel):
  email: EmailStr | None = None
  employeeCode: str | None = Field(default=None, min_length=1)
  officerId: str | None = Field(default=None, min_length=1)
  password : str = Field(..., min_length=1)


class FirebaseLoginRequest(DefaultModel):
  idToken: str = Field(..., min_length=1)


class RefreshRequest(DefaultModel):
  refreshToken : str = Field(..., min_length=1)


class ChangePasswordRequest(DefaultModel):
  oldPassword : str = Field(..., min_length=8)
  newPassword : str = Field(..., min_length=8)

class ForgotPasswordRequest(DefaultModel):
  email: EmailStr

class ResetPasswordRequest(DefaultModel):
  token: str = Field(..., min_length=1)
  newPassword: str = Field(..., min_length=8)


class RecordVoteRequest(DefaultModel):
  voterId: str | None = Field(default=None, min_length=1)
  aadhaarHash: str | None = Field(default=None, min_length=1)
  biometricType: str = Field(..., min_length=1)
  ipAddress: str | None = None
  txHash: str | None = None
  result: str = Field(default='VERIFIED', min_length=1)
