from collections.abc import AsyncIterator

from fastapi import HTTPException, status

from .firebase_client import get_firestore_client


async def get_db() -> AsyncIterator[object]:
  try:
    yield get_firestore_client()
  except RuntimeError as exc:
    raise HTTPException(
      status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
      detail=str(exc),
    ) from exc
