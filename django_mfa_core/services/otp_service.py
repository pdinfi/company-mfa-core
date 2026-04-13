"""Helpers for numeric OTP challenges (email/SMS)."""

from __future__ import annotations

from django.utils import timezone

from django_mfa_core.models import MFASession
from django_mfa_core.utils.encryption import generate_otp_salt, hash_otp
from django_mfa_core.utils.helpers import generate_numeric_otp


def mint_numeric_otp() -> str:
    """Generate a numeric OTP respecting configured length."""
    return generate_numeric_otp()


def attach_otp_to_session(session: MFASession, code: str) -> None:
    """Persist a salted hash of the OTP on the session row."""
    salt = generate_otp_salt()
    session.otp_salt = salt
    session.otp_hash = hash_otp(code, salt)
    session.save(update_fields=["otp_salt", "otp_hash"])


def session_otp_matches(session: MFASession, code: str) -> bool:
    """Constant-time friendly comparison of a user code to the stored hash."""
    if not session.otp_hash or not session.otp_salt:
        return False
    candidate = hash_otp(code, session.otp_salt)
    return candidate == session.otp_hash


def is_session_expired(session: MFASession) -> bool:
    """Return True when the challenge TTL has elapsed."""
    return timezone.now() >= session.expires_at
