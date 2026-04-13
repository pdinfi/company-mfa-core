"""Pluggable MFA providers."""

from django_mfa_core.providers.base import BaseMFAProvider, build_provider_registry
from django_mfa_core.providers.email_provider import EmailMFAProvider
from django_mfa_core.providers.sms_provider import SMSMFAProvider
from django_mfa_core.providers.totp_provider import TOTPMFAProvider

__all__ = [
    "BaseMFAProvider",
    "EmailMFAProvider",
    "SMSMFAProvider",
    "TOTPMFAProvider",
    "build_provider_registry",
]
