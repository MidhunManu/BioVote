import base64
import binascii
import hashlib
import logging
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import HTTPException, Request, status

from .firebase_client import (
  get_firestore_client,
  is_firebase_enabled,
  verify_firebase_token,
)


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Settings:
  TOKEN_SECRET_KEY: str = os.getenv('TOKEN_SECRET_KEY', 'change-me-in-production')
  TOKEN_ENC_ALGORITHM: str = os.getenv('TOKEN_ENC_ALGORITHM', 'HS256')
  API_TOKEN_EXPIRE_MINUTES: int = int(os.getenv('API_TOKEN_EXPIRE_MINUTES', '60'))
  REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv('REFRESH_TOKEN_EXPIRE_DAYS', '7'))
  RESET_TOKEN_EXPIRE_MINUTES: int = int(os.getenv('RESET_TOKEN_EXPIRE_MINUTES', '15'))
  OFFICERS_COLLECTION: str = os.getenv('OFFICERS_COLLECTION', 'booth_officers')
  VOTERS_COLLECTION: str = os.getenv('VOTERS_COLLECTION', 'voters')
  BOOTHS_COLLECTION: str = os.getenv('BOOTHS_COLLECTION', 'booths')
  AUDIT_LOGS_COLLECTION: str = os.getenv('AUDIT_LOGS_COLLECTION', 'audit_logs')


SETTINGS = Settings()
FOUNDING_ENGINEERS: set[int] = set()
_REFRESH_TOKENS: dict[str, dict] = {}
_PASSWORD_RESET_TOKENS: dict[str, dict] = {}


class Auth:
  def __init__(self):
    self._firebase_enabled = is_firebase_enabled()

  def _firebase_active(self) -> bool:
    return self._firebase_enabled

  def _clean_string(self, value):
    if not isinstance(value, str):
      return value

    cleaned = value.strip()
    while len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {"'", '"'}:
      cleaned = cleaned[1:-1].strip()
    return cleaned

  def _public_officer(self, user: dict) -> dict:
    return {
      'id': user['id'],
      'employeeCode': user.get('employee_code'),
      'name': user.get('name'),
      'userType': user.get('user_type'),
      'boothId': user.get('booth_id'),
      'boothName': user.get('booth_name'),
      'isActive': user.get('is_active', True),
    }

  def _public_booth(self, booth: dict) -> dict:
    return {
      'id': booth.get('id'),
      'name': booth.get('name'),
      'address': booth.get('address'),
      'constituency': booth.get('constituency'),
      'isActive': booth.get('isActive', True),
      'totalVoters': booth.get('totalVoters'),
      'votesCast': booth.get('votesCast'),
    }

  def _public_voter(self, voter: dict) -> dict:
    return {
      'id': voter.get('id'),
      'aadhaarHash': voter.get('aadhaarHash'),
      'name': voter.get('name'),
      'address': voter.get('address'),
      'dob': voter.get('dob'),
      'gender': voter.get('gender'),
      'boothId': voter.get('boothId'),
      'boothName': voter.get('boothName'),
      'constituency': voter.get('constituency'),
      'irisTemplate': voter.get('irisTemplate'),
      'photoUrl': voter.get('photoUrl'),
      'hasVoted': voter.get('hasVoted', False),
      'createdAt': voter.get('createdAt'),
    }

  def _map_booth_document(self, snapshot) -> dict | None:
    if not snapshot or not snapshot.exists:
      return None

    data = snapshot.to_dict() or {}
    booth_id = self._clean_string(data.get('id') or snapshot.id)
    return {
      'id': booth_id,
      'name': self._clean_string(data.get('name')),
      'address': self._clean_string(data.get('address')),
      'constituency': self._clean_string(data.get('constituency')),
      'isActive': data.get('is_active', True),
      'totalVoters': data.get('total_voters'),
      'votesCast': data.get('votes_cast'),
      '_ref': snapshot.reference,
    }

  def _map_voter_document(self, snapshot) -> dict | None:
    if not snapshot or not snapshot.exists:
      return None

    data = snapshot.to_dict() or {}
    voter_id = self._clean_string(data.get('id') or snapshot.id)
    return {
      'id': voter_id,
      'aadhaarHash': self._clean_string(data.get('aadhaar_hash')),
      'name': self._clean_string(data.get('name')),
      'address': self._clean_string(data.get('address')),
      'dob': self._clean_string(data.get('dob')),
      'gender': self._clean_string(data.get('gender')),
      'boothId': self._clean_string(data.get('booth_id')),
      'boothName': self._clean_string(data.get('booth_name')),
      'constituency': self._clean_string(data.get('constituency')),
      'irisTemplate': self._clean_string(data.get('iris_template')),
      'photoUrl': self._clean_string(data.get('photo_url')),
      'hasVoted': data.get('has_voted', False),
      'createdAt': data.get('created_at'),
      '_ref': snapshot.reference,
    }

  def _map_audit_log_document(self, snapshot) -> dict | None:
    if not snapshot or not snapshot.exists:
      return None

    data = snapshot.to_dict() or {}
    audit_id = self._clean_string(data.get('id') or snapshot.id)
    return {
      'id': audit_id,
      'aadhaarHash': self._clean_string(data.get('aadhaar_hash')),
      'biometricType': self._clean_string(data.get('biometric_type')),
      'boothId': self._clean_string(data.get('booth_id')),
      'boothName': self._clean_string(data.get('booth_name')),
      'ipAddress': self._clean_string(data.get('ip_address')),
      'officerId': self._clean_string(data.get('officer_id')),
      'result': self._clean_string(data.get('result')),
      'timestamp': data.get('timestamp'),
      'txHash': self._clean_string(data.get('tx_hash')),
      'voterId': self._clean_string(data.get('voter_id')),
      'voterName': self._clean_string(data.get('voter_name')),
    }

  def _normalize_role(self, role: str | None) -> str:
    return self._clean_string(role or 'OFFICER').upper()

  def _map_officer_document(self, snapshot) -> dict | None:
    if not snapshot or not snapshot.exists:
      return None

    data = snapshot.to_dict() or {}
    officer_id = self._clean_string(data.get('id') or snapshot.id)
    return {
      'id': officer_id,
      'email': self._clean_string(data.get('email')),
      'employee_code': self._clean_string(data.get('employee_code')),
      'name': self._clean_string(data.get('name')),
      'password': self._clean_string(data.get('password_hash', '')),
      'user_type': self._normalize_role(data.get('role')),
      'booth_id': self._clean_string(data.get('booth_id')),
      'booth_name': self._clean_string(data.get('booth_name')),
      'is_password_reset': data.get('is_password_reset', True),
      'is_active': data.get('is_active', True),
      '_ref': snapshot.reference,
    }

  def _collection(self, db, name: str):
    client = db or get_firestore_client()
    return client.collection(name)

  def generate_password_hash(self, password: str):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

  def verify_password(self, password: str, hashed: str):
    stored_password = self._clean_string(hashed)
    if not stored_password:
      return False

    if stored_password == password:
      return True

    if stored_password.startswith('$2'):
      return bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8'))

    try:
      binascii.unhexlify(stored_password)
    except (binascii.Error, ValueError):
      return False

    return hashlib.sha256(password.encode('utf-8')).hexdigest() == stored_password.lower()

  def verify_founding_engineer(self, userId: int):
    isMaintenanceMode = False
    if isMaintenanceMode and FOUNDING_ENGINEERS and userId not in FOUNDING_ENGINEERS:
      raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='System is currently in maintenance mode.'
      )

  async def _get_user_by_email(self, db, email: str):
    docs = self._collection(db, SETTINGS.OFFICERS_COLLECTION).where('email', '==', email.lower()).limit(1).stream()
    for doc in docs:
      return self._map_officer_document(doc)
    return None

  async def _get_booth_by_id(self, db, boothId: str):
    cleaned_booth_id = self._clean_string(boothId)
    snapshot = self._collection(db, SETTINGS.BOOTHS_COLLECTION).document(cleaned_booth_id).get()
    booth = self._map_booth_document(snapshot)
    if booth:
      return booth

    docs = self._collection(db, SETTINGS.BOOTHS_COLLECTION).where('id', '==', cleaned_booth_id).limit(1).stream()
    for doc in docs:
      return self._map_booth_document(doc)

    docs = self._collection(db, SETTINGS.BOOTHS_COLLECTION).stream()
    for doc in docs:
      booth = self._map_booth_document(doc)
      if booth and booth.get('id') == cleaned_booth_id:
        return booth
    return None

  async def _get_user_by_employee_code(self, db, employeeCode: str):
    cleaned_employee_code = self._clean_string(employeeCode)
    docs = self._collection(db, SETTINGS.OFFICERS_COLLECTION).where('employee_code', '==', cleaned_employee_code).limit(1).stream()
    for doc in docs:
      return self._map_officer_document(doc)

    docs = self._collection(db, SETTINGS.OFFICERS_COLLECTION).stream()
    for doc in docs:
      user = self._map_officer_document(doc)
      if user and user.get('employee_code') == cleaned_employee_code:
        return user
    return None

  async def _get_user_by_id(self, db, userId: str):
    cleaned_user_id = self._clean_string(userId)
    snapshot = self._collection(db, SETTINGS.OFFICERS_COLLECTION).document(cleaned_user_id).get()
    user = self._map_officer_document(snapshot)
    if user:
      return user

    docs = self._collection(db, SETTINGS.OFFICERS_COLLECTION).where('id', '==', cleaned_user_id).limit(1).stream()
    for doc in docs:
      return self._map_officer_document(doc)

    docs = self._collection(db, SETTINGS.OFFICERS_COLLECTION).stream()
    for doc in docs:
      user = self._map_officer_document(doc)
      if user and user.get('id') == cleaned_user_id:
        return user
    return None

  async def _get_voter_by_id(self, db, voterId: str):
    cleaned_voter_id = self._clean_string(voterId)
    if '/' not in cleaned_voter_id:
      snapshot = self._collection(db, SETTINGS.VOTERS_COLLECTION).document(cleaned_voter_id).get()
      voter = self._map_voter_document(snapshot)
      if voter:
        return voter

    docs = self._collection(db, SETTINGS.VOTERS_COLLECTION).where('id', '==', cleaned_voter_id).limit(1).stream()
    for doc in docs:
      return self._map_voter_document(doc)

    docs = self._collection(db, SETTINGS.VOTERS_COLLECTION).stream()
    for doc in docs:
      voter = self._map_voter_document(doc)
      if voter and voter.get('id') == cleaned_voter_id:
        return voter
    return None

  async def _get_voter_by_aadhaar_hash(self, db, aadhaarHash: str):
    cleaned_hash = self._clean_string(aadhaarHash)
    docs = self._collection(db, SETTINGS.VOTERS_COLLECTION).where('aadhaar_hash', '==', cleaned_hash).limit(1).stream()
    for doc in docs:
      return self._map_voter_document(doc)

    docs = self._collection(db, SETTINGS.VOTERS_COLLECTION).stream()
    for doc in docs:
      voter = self._map_voter_document(doc)
      if voter and voter.get('aadhaarHash') == cleaned_hash:
        return voter
    return None

  async def _upsert_user_password(self, db, userId: str, hashedPassword: str):
    user = await self._get_user_by_id(db, userId)
    if not user:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail='User not found'
      )
    user['_ref'].update({
      'password_hash': hashedPassword,
      'is_password_reset': True,
    })

  async def _store_refresh_token(self, db, userId: str, token: str, expiry: datetime):
    user = await self._get_user_by_id(db, userId)
    if not user:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail='User not found'
      )
    _REFRESH_TOKENS[token] = {
      'user_id': userId,
      'user_type': user['user_type'],
      'expires_at': expiry,
    }

  async def _get_refresh_token_record(self, db, refreshToken: str):
    return _REFRESH_TOKENS.get(refreshToken)

  async def _delete_refresh_token(self, db, userId: str):
    for token, data in list(_REFRESH_TOKENS.items()):
      if data['user_id'] == userId:
        del _REFRESH_TOKENS[token]
        return
    raise HTTPException(
      status_code=status.HTTP_404_NOT_FOUND,
      detail='User profile not found'
    )

  async def _store_password_reset_token(self, db, hashedToken: str, userId: str, expiry: datetime):
    _PASSWORD_RESET_TOKENS[hashedToken] = {
      'token': hashedToken,
      'user_id': userId,
      'expires_at': expiry,
    }

  async def _get_password_reset_token(self, db, hashedToken: str):
    return _PASSWORD_RESET_TOKENS.get(hashedToken)

  async def _delete_password_reset_tokens_for_user(self, db, userId: str):
    for token in [token for token, data in _PASSWORD_RESET_TOKENS.items() if data['user_id'] == userId]:
      del _PASSWORD_RESET_TOKENS[token]

  async def generate_refresh_token(self, userId: str, db):
    token = base64.urlsafe_b64encode(os.urandom(48)).decode('utf-8').rstrip('=')
    expiry = datetime.now(timezone.utc) + timedelta(days=SETTINGS.REFRESH_TOKEN_EXPIRE_DAYS)
    await self._store_refresh_token(db, userId, token, expiry)
    return token, expiry

  def generate_api_token(self, userId: str, userType: str):
    payload = {
      'userId': userId,
      'userType': userType,
      'exp': datetime.now(timezone.utc) + timedelta(minutes=SETTINGS.API_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SETTINGS.TOKEN_SECRET_KEY, algorithm=SETTINGS.TOKEN_ENC_ALGORITHM)

  def verify_api_token(self, token: str):
    try:
      payload = jwt.decode(
        token,
        SETTINGS.TOKEN_SECRET_KEY,
        algorithms=[SETTINGS.TOKEN_ENC_ALGORITHM]
      )
      return payload['userId'], payload['userType']
    except jwt.ExpiredSignatureError as exc:
      raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Token expired.') from exc
    except jwt.InvalidSignatureError as exc:
      raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid signature.') from exc
    except Exception as e:
      logger.exception('Error validating api token %s', e)
      raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Error validating token.'
      ) from e

  async def login_with_firebase(self, db, firebaseToken: str):
    if not self._firebase_active():
      raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail='Firebase authentication is not configured.'
      )

    try:
      decoded = verify_firebase_token(firebaseToken)
    except Exception as e:
      logger.exception('Firebase token validation failed: %s', e)
      raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Invalid Firebase token.'
      ) from e

    email = decoded.get('email')
    employee_code = decoded.get('employee_code') or decoded.get('employeeCode')
    officer_id = decoded.get('officer_id') or decoded.get('officerId')

    user = None
    if officer_id:
      user = await self._get_user_by_id(db, officer_id)
    if not user and employee_code:
      user = await self._get_user_by_employee_code(db, employee_code)
    if not user and email:
      user = await self._get_user_by_email(db, email.lower())

    if not user:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail='Officer not found.'
      )

    userId = user['id']
    userType = user['user_type']
    refreshToken, _ = await self.generate_refresh_token(userId, db)
    apiToken = self.generate_api_token(userId, userType)

    self.verify_founding_engineer(userId)
    return {
      'userId': userId,
      'refreshToken': refreshToken,
      'APIToken': apiToken,
      'userType': userType,
      'isPasswordReset': user.get('is_password_reset', False),
      'officer': self._public_officer(user),
    }

  async def login(
    self,
    db,
    password: str,
    email: str | None = None,
    employeeCode: str | None = None,
    officerId: str | None = None,
  ):
    user = None
    if officerId:
      user = await self._get_user_by_id(db, officerId)
    if not user and employeeCode:
      user = await self._get_user_by_employee_code(db, employeeCode)
    if not user and email:
      user = await self._get_user_by_email(db, email)
    if not any([officerId, employeeCode, email]):
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail='Provide officerId, employeeCode, or email.'
      )

    if not user or not self.verify_password(password, user['password']):
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail='Incorrect officer credentials.'
      )
    if not user.get('is_active', True):
      raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Officer is inactive.'
      )

    userId = user['id']
    userType = user['user_type']
    refreshToken, _ = await self.generate_refresh_token(userId, db)
    apiToken = self.generate_api_token(userId, userType)

    self.verify_founding_engineer(userId)
    return {
      'userId': userId,
      'refreshToken': refreshToken,
      'APIToken': apiToken,
      'userType': userType,
      'isPasswordReset': user.get('is_password_reset', False),
      'boothId': user.get('booth_id'),
      'boothName': user.get('booth_name'),
      'name': user.get('name'),
      'employeeCode': user.get('employee_code'),
      'officer': self._public_officer(user),
    }

  async def get_officer_profile(self, db, officerId: str):
    user = await self._get_user_by_id(db, officerId)
    if not user:
      raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Officer not found')
    return self._public_officer(user)

  async def list_booth_officers(self, db, boothId: str | None = None, activeOnly: bool | None = None):
    officers: list[dict] = []
    cleaned_booth_id = self._clean_string(boothId) if boothId else None
    for doc in self._collection(db, SETTINGS.OFFICERS_COLLECTION).stream():
      user = self._map_officer_document(doc)
      if not user:
        continue
      if cleaned_booth_id and user.get('booth_id') != cleaned_booth_id:
        continue
      if activeOnly is not None and bool(user.get('is_active', True)) != activeOnly:
        continue
      officers.append(self._public_officer(user))
    return officers

  async def get_booth(self, db, boothId: str):
    booth = await self._get_booth_by_id(db, boothId)
    if not booth:
      raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Booth not found')
    return self._public_booth(booth)

  async def get_voter(self, db, voterId: str | None = None, aadhaarHash: str | None = None):
    voter = None
    if voterId:
      voter = await self._get_voter_by_id(db, voterId)
    if not voter and aadhaarHash:
      voter = await self._get_voter_by_aadhaar_hash(db, aadhaarHash)
    if not voter:
      raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Voter not found')
    return self._public_voter(voter)

  async def list_voters(self, db, boothId: str | None = None, hasVoted: bool | None = None):
    voters: list[dict] = []
    cleaned_booth_id = self._clean_string(boothId) if boothId else None
    for doc in self._collection(db, SETTINGS.VOTERS_COLLECTION).stream():
      voter = self._map_voter_document(doc)
      if not voter:
        continue
      if cleaned_booth_id and voter.get('boothId') != cleaned_booth_id:
        continue
      if hasVoted is not None and bool(voter.get('hasVoted', False)) != hasVoted:
        continue
      voters.append(self._public_voter(voter))
    return voters

  async def list_audit_logs(
    self,
    db,
    boothId: str | None = None,
    officerId: str | None = None,
    voterId: str | None = None,
    result: str | None = None,
    limit: int = 50,
  ):
    cleaned_booth_id = self._clean_string(boothId) if boothId else None
    cleaned_officer_id = self._clean_string(officerId) if officerId else None
    cleaned_voter_id = self._clean_string(voterId) if voterId else None
    cleaned_result = self._clean_string(result).upper() if result else None

    logs: list[dict] = []
    for doc in self._collection(db, SETTINGS.AUDIT_LOGS_COLLECTION).stream():
      log = self._map_audit_log_document(doc)
      if not log:
        continue
      if cleaned_booth_id and log.get('boothId') != cleaned_booth_id:
        continue
      if cleaned_officer_id and log.get('officerId') != cleaned_officer_id:
        continue
      if cleaned_voter_id and log.get('voterId') != cleaned_voter_id:
        continue
      if cleaned_result and (log.get('result') or '').upper() != cleaned_result:
        continue
      logs.append(log)

    logs.sort(key=lambda item: item.get('timestamp') or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return logs[:limit]

  async def record_vote(
    self,
    db,
    officerId: str,
    biometricType: str,
    voterId: str | None = None,
    aadhaarHash: str | None = None,
    ipAddress: str | None = None,
    txHash: str | None = None,
    result: str = 'VERIFIED',
  ):
    if not voterId and not aadhaarHash:
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail='Provide voterId or aadhaarHash.'
      )

    officer = await self._get_user_by_id(db, officerId)
    if not officer:
      raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Officer not found')
    if not officer.get('is_active', True):
      raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Officer is inactive.')

    voter = await self.get_voter(db, voterId=voterId, aadhaarHash=aadhaarHash)
    if voter.get('hasVoted'):
      raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Voter has already voted.')
    if officer.get('booth_id') and voter.get('boothId') and officer.get('booth_id') != voter.get('boothId'):
      raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Officer cannot record votes for a different booth.'
      )

    booth = await self._get_booth_by_id(db, voter.get('boothId') or officer.get('booth_id'))
    if booth and not booth.get('isActive', True):
      raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Booth is inactive.')

    voter['_ref'].update({
      'has_voted': True,
    })

    if booth:
      current_votes = booth.get('votesCast') or 0
      booth['_ref'].update({
        'votes_cast': int(current_votes) + 1,
      })

    audit_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc)
    normalized_result = self._clean_string(result).upper()
    audit_payload = {
      'id': audit_id,
      'aadhaar_hash': voter.get('aadhaarHash'),
      'biometric_type': self._clean_string(biometricType).upper(),
      'booth_id': voter.get('boothId') or officer.get('booth_id'),
      'booth_name': voter.get('boothName') or officer.get('booth_name'),
      'ip_address': self._clean_string(ipAddress),
      'officer_id': officer.get('id'),
      'result': normalized_result,
      'timestamp': timestamp,
      'tx_hash': self._clean_string(txHash),
      'voter_id': voter.get('id'),
      'voter_name': voter.get('name'),
    }
    self._collection(db, SETTINGS.AUDIT_LOGS_COLLECTION).document(audit_id).set(audit_payload)

    return {
      'auditLogId': audit_id,
      'result': normalized_result,
      'voter': {
        'id': voter.get('id'),
        'name': voter.get('name'),
        'hasVoted': True,
        'boothId': voter.get('boothId'),
        'boothName': voter.get('boothName'),
      },
      'officer': self._public_officer(officer),
      'booth': self._public_booth(booth) if booth else None,
      'timestamp': timestamp,
    }

  async def verify_request(self, request: Request):
    header = request.headers.get('Authorization')
    if not header or not header.startswith('Bearer '):
      raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Missing auth token.')

    apiToken = header.removeprefix('Bearer ').strip()
    try:
      return self.verify_api_token(apiToken)
    except HTTPException:
      if not self._firebase_active():
        raise

    try:
      decoded = verify_firebase_token(apiToken)
      email = decoded.get('email')
      employee_code = decoded.get('employee_code') or decoded.get('employeeCode')
      officer_id = decoded.get('officer_id') or decoded.get('officerId')

      user = None
      if officer_id:
        user = await self._get_user_by_id(None, officer_id)
      if not user and employee_code:
        user = await self._get_user_by_employee_code(None, employee_code)
      if not user and email:
        user = await self._get_user_by_email(None, email.lower())
      if user:
        return user['id'], user['user_type']
    except HTTPException:
      raise
    except Exception as e:
      logger.exception('Error validating firebase bearer token %s', e)

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token.')

  async def validate_refresh_token(self, db, refreshToken: str):
    storedToken = await self._get_refresh_token_record(db, refreshToken)
    if not storedToken:
      raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid refresh token.')
    if storedToken['expires_at'] < datetime.now(timezone.utc):
      raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Expired refresh token.')
    return storedToken['user_id'], storedToken['user_type']

  async def refresh_api_token(self, refreshToken: str, db):
    userId, userType = await self.validate_refresh_token(db, refreshToken)
    apiToken = self.generate_api_token(userId, userType)
    newRefreshToken, _ = await self.generate_refresh_token(userId, db)
    self.verify_founding_engineer(userId)
    return {
      'userId': userId,
      'userType': userType,
      'APIToken': apiToken,
      'refreshToken': newRefreshToken,
    }

  async def verify_request_role(self, request: Request, role: str):
    userId, userType = await self.verify_request(request)
    if userType.upper() != role.upper():
      raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not enough permissions')
    return userId, userType

  async def invalidate_user(self, userId: str, db):
    await self._delete_refresh_token(db, userId)
    return True

  async def change_password(self, db, userId: str, userType: str, oldPassword: str, newPassword: str):
    user = await self._get_user_by_id(db, userId)
    if not user:
      raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User profile not found')
    if not self.verify_password(oldPassword, user['password']):
      raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Incorrect password')
    await self._upsert_user_password(db, userId, self.generate_password_hash(newPassword))
    return True

  async def forgot_password(self, db, email: str):
    user = await self._get_user_by_email(db, email)
    if not user or not user.get('is_active', True):
      raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
    resetToken = secrets.token_urlsafe(64)
    hashedToken = hashlib.sha256(resetToken.encode()).hexdigest()
    expiry = datetime.now(timezone.utc) + timedelta(minutes=SETTINGS.RESET_TOKEN_EXPIRE_MINUTES)
    await self._store_password_reset_token(db, hashedToken, user['id'], expiry)
    logger.info('Generated password reset token for %s: %s', email, resetToken)

  async def reset_password(self, db, passwordResetToken: str, newPassword: str):
    hashedToken = hashlib.sha256(passwordResetToken.encode()).hexdigest()
    tokenRow = await self._get_password_reset_token(db, hashedToken)
    if not tokenRow:
      raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid password reset token')
    if tokenRow['expires_at'] < datetime.now(timezone.utc):
      raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Token has expired. Please try again'
      )
    await self._delete_password_reset_tokens_for_user(db, tokenRow['user_id'])
    await self._upsert_user_password(db, tokenRow['user_id'], self.generate_password_hash(newPassword))
