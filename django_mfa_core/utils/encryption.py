"""Fernet-based secret encryption for stored TOTP seeds."""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings as django_settings

from django_mfa_core.exceptions import MFAConfigurationError


def _derive_key_from_secret_key() -> bytes:
    digest = hashlib.sha256(django_settings.SECRET_KEY.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def get_fernet() -> Fernet:
    """Return a Fernet instance using project configuration."""
    raw = getattr(django_settings, "MFA_ENCRYPTION_KEY", None)
    if raw:
        if isinstance(raw, str):
            key = raw.encode("utf-8")
        else:
            key = raw
    else:
        key = _derive_key_from_secret_key()
    try:
        return Fernet(key)
    except Exception as exc:  # pragma: no cover - defensive
        raise MFAConfigurationError("Invalid MFA_ENCRYPTION_KEY or Fernet key material.") from exc


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a TOTP shared secret for database storage."""
    token = get_fernet().encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a stored TOTP shared secret."""
    try:
        value = get_fernet().decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as exc:
        raise MFAConfigurationError("Unable to decrypt MFA secret; check MFA_ENCRYPTION_KEY.") from exc
    return value.decode("utf-8")


def generate_otp_salt() -> str:
    """Return a URL-safe random salt for OTP hashing."""
    return base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("=")


def hash_otp(code: str, salt: str) -> str:
    """Create a deterministic hash for a one-time passcode."""
    payload = f"{salt}:{code}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def hash_backup_code(code: str, *, pepper: Optional[str] = None) -> str:
    """Hash a backup code with optional application-level pepper."""
    secret = django_settings.SECRET_KEY if pepper is None else pepper
    payload = f"{secret}:{code}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
