import os
from pathlib import Path

from .config import PROJECT_ROOT

try:
    import firebase_admin
    from firebase_admin import auth, credentials, firestore
except ImportError:
    firebase_admin = None
    auth = None
    credentials = None
    firestore = None


_SERVICE_ACCOUNT_ENV = "FIREBASE_SERVICE_ACCOUNT_PATH"


def _get_service_account_path() -> Path | None:
    configured_path = os.getenv(_SERVICE_ACCOUNT_ENV)
    if configured_path:
        path = Path(configured_path).expanduser()
        if not path.is_absolute():
            path = (PROJECT_ROOT / path).resolve()
        if path.exists():
            return path

    fallback_paths = (
        PROJECT_ROOT / "firebase-service-account.json",
        Path(__file__).resolve().parent / "firebase-service-account.json",
    )
    for path in fallback_paths:
        if path.exists():
            return path
    return None


def is_firebase_enabled() -> bool:
    return firebase_admin is not None and _get_service_account_path() is not None


def get_firebase_app():
    if firebase_admin is None or credentials is None:
        raise RuntimeError(
            "firebase-admin is not installed. Install project dependencies to enable Firebase."
        )

    if firebase_admin._apps:
        return firebase_admin.get_app()

    service_account_path = _get_service_account_path()
    if service_account_path is None:
        raise RuntimeError(
            "Firebase is not configured. Set FIREBASE_SERVICE_ACCOUNT_PATH or add "
            "firebase-service-account.json to the project root."
        )

    cred = credentials.Certificate(str(service_account_path))
    return firebase_admin.initialize_app(cred)


def get_firestore_client():
    if firestore is None:
        raise RuntimeError(
            "firebase-admin is not installed. Install project dependencies to enable Firestore."
        )
    return firestore.client(get_firebase_app())


def verify_firebase_token(id_token: str):
    if auth is None:
        raise RuntimeError(
            "firebase-admin is not installed. Install project dependencies to enable Firebase."
        )
    return auth.verify_id_token(id_token, app=get_firebase_app())
