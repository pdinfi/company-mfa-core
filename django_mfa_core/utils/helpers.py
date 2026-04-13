"""Small helpers shared across services."""

from __future__ import annotations

import secrets
import string
from typing import Optional
from uuid import UUID

from django_mfa_core.settings import get_mfa_settings


def normalize_workspace_id(raw: Optional[str | UUID]) -> Optional[UUID]:
    """Coerce optional workspace identifiers to UUID objects."""
    if raw is None:
        return None
    if isinstance(raw, UUID):
        return raw
    return UUID(str(raw))


def generate_numeric_otp(length: Optional[int] = None) -> str:
    """Generate a numeric OTP of configured length."""
    cfg = get_mfa_settings()
    size = length or int(cfg.get("OTP_LENGTH", 6))
    alphabet = string.digits
    return "".join(secrets.choice(alphabet) for _ in range(size))


def get_client_ip(request) -> Optional[str]:
    """Best-effort client IP extraction."""
    meta = getattr(request, "META", {})
    forwarded = meta.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return meta.get("REMOTE_ADDR")
