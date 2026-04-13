"""Abstract base provider for MFA transports."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Dict, Type

if TYPE_CHECKING:
    from django_mfa_core.models import MFASession

    from django.contrib.auth.models import AbstractBaseUser


class BaseMFAProvider(ABC):
    """Pluggable MFA provider."""

    name: str

    @abstractmethod
    def send_challenge(
        self,
        *,
        user: "AbstractBaseUser",
        session: "MFASession",
        plaintext_code: str,
        workspace_id,
        request=None,
    ) -> None:
        """Deliver an out-of-band one-time code to the user."""

    @abstractmethod
    def verify(
        self,
        *,
        user: "AbstractBaseUser",
        code: str,
        workspace_id,
        request=None,
    ) -> bool:
        """Verify a user-supplied code for this provider type.

        For channel-based OTP the service layer compares hashed values; providers
        may return ``False`` and defer to the service, or implement validation.
        """


def build_provider_registry() -> Dict[str, Type[BaseMFAProvider]]:
    """Map provider names to concrete classes."""
    from django_mfa_core.providers.email_provider import EmailMFAProvider
    from django_mfa_core.providers.sms_provider import SMSMFAProvider
    from django_mfa_core.providers.totp_provider import TOTPMFAProvider

    return {
        EmailMFAProvider.name: EmailMFAProvider,
        SMSMFAProvider.name: SMSMFAProvider,
        TOTPMFAProvider.name: TOTPMFAProvider,
    }
