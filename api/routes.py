from fastapi import (
  APIRouter,
  Depends,
  HTTPException,
  Query,
  status,
  Request,
)
from .database import get_db
from .service_runtime import Auth
from .schemas import (
  LoginRequest,
  FirebaseLoginRequest,
  RefreshRequest,
  ChangePasswordRequest,
  ForgotPasswordRequest,
  ResetPasswordRequest,
  RecordVoteRequest,
)

ROUTER = APIRouter()

async def verify_request(request : Request):
  return await Auth().verify_request(request)

async def require_admin(request: Request):
  return await Auth().verify_request_role(request, 'ADMIN')

async def require_officer(request: Request):
  return await Auth().verify_request_role(request, 'OFFICER')

# @ROUTER.get('/pass')
# async def get_new_pass(password):
#   return Auth().generate_password_hash(password)

@ROUTER.post('/login', status_code=status.HTTP_200_OK)
async def login(request : LoginRequest, db = Depends(get_db)):
  data = await Auth().login(
    db,
    password=request.password,
    email=request.email.lower() if request.email else None,
    employeeCode=request.employeeCode,
    officerId=request.officerId,
  )
  return {
    'statusCode' : status.HTTP_200_OK,
    'data' : data
  }

@ROUTER.post('/login/firebase', status_code=status.HTTP_200_OK)
async def firebase_login(request: FirebaseLoginRequest, db = Depends(get_db)):
  data = await Auth().login_with_firebase(db, request.idToken)
  return {
    'statusCode': status.HTTP_200_OK,
    'data': data
  }

@ROUTER.post('/logout/{userId}', status_code=status.HTTP_204_NO_CONTENT)
async def logout_admin(
  userId: str,
  db = Depends(get_db),
  auth: tuple[str, str] = Depends(require_admin),
):
  authUserId, _ = auth
  if authUserId != userId:
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
  await Auth().invalidate_user(userId, db)
  return {
    'statusCode' : status.HTTP_204_NO_CONTENT,
  }


@ROUTER.post('/refresh', status_code=status.HTTP_200_OK)
async def refresh(request: RefreshRequest, db = Depends(get_db)):
  data = await Auth().refresh_api_token(request.refreshToken, db)
  return {
    'statusCode' : status.HTTP_200_OK,
    'data' : data
  }

@ROUTER.get('/me', status_code=status.HTTP_200_OK)
async def get_me(
  db = Depends(get_db),
  auth: tuple[str, str] = Depends(verify_request),
):
  userId, _ = auth
  data = await Auth().get_officer_profile(db, userId)
  return {
    'statusCode': status.HTTP_200_OK,
    'data': data,
  }

@ROUTER.get('/booths/{boothId}', status_code=status.HTTP_200_OK)
async def get_booth(
  boothId: str,
  db = Depends(get_db),
  auth: tuple[str, str] = Depends(verify_request),
):
  data = await Auth().get_booth(db, boothId)
  return {
    'statusCode': status.HTTP_200_OK,
    'data': data,
  }

@ROUTER.get('/booth-officers', status_code=status.HTTP_200_OK)
async def list_booth_officers(
  boothId: str | None = Query(default=None),
  activeOnly: bool | None = Query(default=None),
  db = Depends(get_db),
  auth: tuple[str, str] = Depends(verify_request),
):
  data = await Auth().list_booth_officers(db, boothId=boothId, activeOnly=activeOnly)
  return {
    'statusCode': status.HTTP_200_OK,
    'data': data,
  }

@ROUTER.get('/booth-officers/{officerId}', status_code=status.HTTP_200_OK)
async def get_booth_officer(
  officerId: str,
  db = Depends(get_db),
  auth: tuple[str, str] = Depends(verify_request),
):
  data = await Auth().get_officer_profile(db, officerId)
  return {
    'statusCode': status.HTTP_200_OK,
    'data': data,
  }

@ROUTER.get('/voters', status_code=status.HTTP_200_OK)
async def list_voters(
  boothId: str | None = Query(default=None),
  hasVoted: bool | None = Query(default=None),
  db = Depends(get_db),
  auth: tuple[str, str] = Depends(verify_request),
):
  data = await Auth().list_voters(db, boothId=boothId, hasVoted=hasVoted)
  return {
    'statusCode': status.HTTP_200_OK,
    'data': data,
  }

@ROUTER.get('/voters/{voterId}', status_code=status.HTTP_200_OK)
async def get_voter(
  voterId: str,
  db = Depends(get_db),
  auth: tuple[str, str] = Depends(verify_request),
):
  data = await Auth().get_voter(db, voterId=voterId)
  return {
    'statusCode': status.HTTP_200_OK,
    'data': data,
  }

@ROUTER.get('/voters/by-aadhaar/{aadhaarHash}', status_code=status.HTTP_200_OK)
async def get_voter_by_aadhaar(
  aadhaarHash: str,
  db = Depends(get_db),
  auth: tuple[str, str] = Depends(verify_request),
):
  data = await Auth().get_voter(db, aadhaarHash=aadhaarHash)
  return {
    'statusCode': status.HTTP_200_OK,
    'data': data,
  }

@ROUTER.post('/votes/record', status_code=status.HTTP_202_ACCEPTED)
async def record_vote(
  http_request: Request,
  request: RecordVoteRequest,
  db = Depends(get_db),
  auth: tuple[str, str] = Depends(require_officer),
):
  officerId, _ = auth
  data = await Auth().record_vote(
    db,
    officerId=officerId,
    voterId=request.voterId,
    aadhaarHash=request.aadhaarHash,
    biometricType=request.biometricType,
    ipAddress=http_request.client.host if http_request.client else None,
    txHash=request.txHash,
    result=request.result,
  )
  return {
    'statusCode': status.HTTP_202_ACCEPTED,
    'data': data,
  }

@ROUTER.get('/audit-logs', status_code=status.HTTP_200_OK)
async def list_audit_logs(
  boothId: str | None = Query(default=None),
  officerId: str | None = Query(default=None),
  voterId: str | None = Query(default=None),
  result: str | None = Query(default=None),
  limit: int = Query(default=50, ge=1, le=200),
  db = Depends(get_db),
  auth: tuple[str, str] = Depends(verify_request),
):
  data = await Auth().list_audit_logs(
    db,
    boothId=boothId,
    officerId=officerId,
    voterId=voterId,
    result=result,
    limit=limit,
  )
  return {
    'statusCode': status.HTTP_200_OK,
    'data': data,
  }

@ROUTER.post('/change-password', status_code=status.HTTP_202_ACCEPTED)
async def change_password(
  request: ChangePasswordRequest,
  db = Depends(get_db),
  auth: tuple[str, str] = Depends(verify_request)
):
  userId, userType = auth
  await Auth().change_password(
    db,
    userId,
    userType,
    request.oldPassword,
    request.newPassword,
  )
  return {
    'statusCode' : status.HTTP_202_ACCEPTED,
  }

@ROUTER.post('/forgot-password', status_code=status.HTTP_202_ACCEPTED)
async def forgot_password(
  request: ForgotPasswordRequest,
  db = Depends(get_db),
):
  await Auth().forgot_password(
    db,
    request.email,
  )
  return {
    'statusCode': status.HTTP_202_ACCEPTED,
  }

@ROUTER.post('/reset-password', status_code=status.HTTP_202_ACCEPTED)
async def reset_password(
  request: ResetPasswordRequest,
  db = Depends(get_db),
):
  await Auth().reset_password(
    db,
    request.token,
    request.newPassword
  )
  return {
    'statusCode': status.HTTP_202_ACCEPTED,
  }
