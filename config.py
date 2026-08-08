import os
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()

HAS_APP_CONFIG = any(
    str(os.getenv(key, "")).strip()
    for key in ("TUURIO_ISSUER", "TUURIO_CLIENT_ID", "TUURIO_CLIENT_SECRET", "TUURIO_REDIRECT_URI")
)


def _normalize_authority(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _normalize_url(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return raw


def _sanitize_client_id(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw or len(raw) > 120:
        return None
    for char in raw:
        if not (char.isalnum() or char in "._-"):
            return None
    return raw


def _sanitize_scope(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    cleaned_parts = []
    for part in raw.split():
        if all(ch.isalnum() or ch in "._:-" for ch in part):
            cleaned_parts.append(part)
    if not cleaned_parts:
        return None
    return " ".join(cleaned_parts)


def _normalize_webhook_path(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if not raw.startswith("/") or " " in raw:
        return None
    return raw


def _sanitize_header_name(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw or len(raw) > 120:
        return None
    if not all(ch.isalnum() or ch == "-" for ch in raw):
        return None
    return raw


AUTHORITY = _normalize_authority(os.getenv("TUURIO_ISSUER")) or "https://your-tenant.id.tuurio.com"
AUTHORIZE_ENDPOINT = f"{AUTHORITY}/oauth2/authorize"
TOKEN_ENDPOINT = f"{AUTHORITY}/oauth2/token"
DISCOVERY_ENDPOINT = f"{AUTHORITY}/.well-known/openid-configuration"

CLIENT_ID = _sanitize_client_id(os.getenv("TUURIO_CLIENT_ID")) or "replace-after-browser-handoff"
CLIENT_SECRET = os.getenv("TUURIO_CLIENT_SECRET", "")

REDIRECT_URI = _normalize_url(os.getenv("TUURIO_REDIRECT_URI")) or "http://localhost:8083/auth/callback"
POST_LOGOUT_REDIRECT_URI = (
    _normalize_url(os.getenv("TUURIO_POST_LOGOUT_REDIRECT_URI")) or "http://localhost:8083/logout/callback"
)
SCOPE = _sanitize_scope(os.getenv("TUURIO_SCOPE")) or "openid profile email"

SECRET_KEY = os.getenv("TUURIO_SESSION_SECRET", "development-only-change-before-deploy")
SESSION_DIR = os.getenv(
    "TUURIO_SESSION_DIR",
    str(Path(__file__).resolve().parent / ".flask_session"),
)

WEBHOOK_ID = str(os.getenv("TUURIO_WEBHOOK_ID", "")).strip()
WEBHOOK_URL = _normalize_url(os.getenv("TUURIO_WEBHOOK_URL")) or ""
WEBHOOK_EDIT_URL = _normalize_url(os.getenv("TUURIO_WEBHOOK_EDIT_URL")) or ""
WEBHOOK_SIGNING_SECRET = str(os.getenv("TUURIO_WEBHOOK_SIGNING_SECRET", "")).strip()
WEBHOOK_LISTEN_PATH = _normalize_webhook_path(os.getenv("TUURIO_WEBHOOK_LISTEN_PATH")) or "/webhooks/tuurio"
WEBHOOK_API_KEY_HEADER = _sanitize_header_name(os.getenv("TUURIO_WEBHOOK_API_KEY_HEADER")) or "X-Tuurio-Webhook-Key"
WEBHOOK_API_KEY = str(os.getenv("TUURIO_WEBHOOK_API_KEY", "")).strip()
