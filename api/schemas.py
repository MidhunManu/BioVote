from pydantic import (
  BaseModel,
  Field,
  EmailStr,
  root_validator,
)


class DefaultModel(BaseModel):
  class Config:
    from_attributes = True


class LoginRequest(DefaultModel):
  email: EmailStr | None = None
  employeeCode: str | None = Field(default=None, min_length=1)
  officerId: str | None = Field(default=None, min_length=1)
  password : str = Field(..., min_length=1)

  @root_validator(skip_on_failure=True)
  def require_login_identifier(cls, values):
    if not any([
      values.get('email'),
      values.get('employeeCode'),
      values.get('officerId'),
    ]):
      raise ValueError('At least one of email, employeeCode, or officerId must be provided.')
    return values


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
  txHash: str | None = None
  result: str = Field(default='VERIFIED', min_length=1)

  @root_validator(skip_on_failure=True)
  def require_voter_identifier(cls, values):
    if not any([
      values.get('voterId'),
      values.get('aadhaarHash'),
    ]):
      raise ValueError('At least one of voterId or aadhaarHash must be provided.')
    return values
