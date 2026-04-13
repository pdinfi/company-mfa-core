"""MFA settings resolution with safe defaults."""

from __future__ import annotations

from typing import Any

from django.conf import settings as django_settings

from django_mfa_core.exceptions import MFAConfigurationError
from django_mfa_core.utils.totp_app_config import validate_totp_apps_config

DEFAULT_MFA_SETTINGS: dict[str, Any] = {
    "ENABLED": True,
    "PROVIDERS": ["totp", "email"],
    "OTP_EXPIRY": 60,
    "MAX_ATTEMPTS": 5,
    "TRUST_DEVICE_DAYS": 7,
    "ENFORCE_MIDDLEWARE": True,
    "MIDDLEWARE_EXEMPT_PREFIXES": [
        "/admin/login/",
        "/static/",
        "/media/",
    ],
    "MFA_URL_PREFIX": "/mfa/",
    "RATE_LIMIT_BACKEND": "memory",
    "REDIS_URL": None,
    "EMAIL_FROM": None,
    "OTP_LENGTH": 6,
    "BACKUP_CODE_COUNT": 10,
    "INITIATE_RATE_LIMIT": "5/m",
    "VERIFY_RATE_LIMIT": "30/m",
    "CELERY_OTP": False,
    "VERIFY_REDIRECT_URL": "/mfa/verify/",
    # Pluggable TOTP / authenticator-app labels (Google, Microsoft, AWS VMFA, etc. are standard TOTP).
    "TOTP_APPS": [],
    "TOTP_DEFAULT_ISSUER": None,
    "TOTP_RESOLVER": None,
}


def get_mfa_settings() -> dict[str, Any]:
    """Return merged MFA settings from Django settings.

    Raises:
        MFAConfigurationError: If critical configuration is inconsistent.
    """
    user_cfg = getattr(django_settings, "MFA_SETTINGS", {}) or {}
    if not isinstance(user_cfg, dict):
        raise MFAConfigurationError("MFA_SETTINGS must be a dict.")
    merged = {**DEFAULT_MFA_SETTINGS, **user_cfg}
    if merged["ENABLED"] and merged["RATE_LIMIT_BACKEND"] == "redis" and not merged.get("REDIS_URL"):
        raise MFAConfigurationError("REDIS_URL is required when RATE_LIMIT_BACKEND is 'redis'.")
    apps = merged.get("TOTP_APPS")
    if apps is None:
        merged["TOTP_APPS"] = []
        apps = []
    validate_totp_apps_config(apps)
    tr = merged.get("TOTP_RESOLVER")
    if tr is not None and not callable(tr):
        raise MFAConfigurationError("TOTP_RESOLVER must be a callable or None.")
    return merged
