"""Shared constants for MFA types and audit actions."""

from __future__ import annotations

from typing import Final

DEVICE_TYPE_TOTP: Final[str] = "totp"
DEVICE_TYPE_EMAIL: Final[str] = "email"
DEVICE_TYPE_SMS: Final[str] = "sms"

DEVICE_TYPE_CHOICES: Final[tuple[tuple[str, str], ...]] = (
    (DEVICE_TYPE_TOTP, "TOTP"),
    (DEVICE_TYPE_EMAIL, "Email OTP"),
    (DEVICE_TYPE_SMS, "SMS OTP"),
)

AUDIT_ACTION_CHALLENGE_CREATED: Final[str] = "challenge_created"
AUDIT_ACTION_CHALLENGE_VERIFIED: Final[str] = "challenge_verified"
AUDIT_ACTION_CHALLENGE_FAILED: Final[str] = "challenge_failed"
AUDIT_ACTION_DEVICE_ENABLED: Final[str] = "device_enabled"
AUDIT_ACTION_DEVICE_DISABLED: Final[str] = "device_disabled"
AUDIT_ACTION_BACKUP_USED: Final[str] = "backup_code_used"

SESSION_KEY_MFA_VERIFIED_AT: Final[str] = "mfa_verified_at"
SESSION_KEY_MFA_TRUST_UNTIL: Final[str] = "mfa_trust_until"
SESSION_KEY_MFA_PENDING_CHALLENGE: Final[str] = "mfa_pending_challenge_id"

DEFAULT_ISSUER: Final[str] = "django-mfa-core"
