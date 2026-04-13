"""Email delivery for OTP challenges (console-friendly by default)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from django.conf import settings as django_settings
from django.core.mail import send_mail

from django_mfa_core.exceptions import MFAProviderError
from django_mfa_core.providers.base import BaseMFAProvider
from django_mfa_core.settings import get_mfa_settings

if TYPE_CHECKING:
    from django_mfa_core.models import MFASession

    from django.contrib.auth.models import AbstractBaseUser


class EmailMFAProvider(BaseMFAProvider):
    """Sends numeric OTPs using Django's email framework."""

    name = "email"

    def send_challenge(
        self,
        *,
        user: "AbstractBaseUser",
        session: "MFASession",
        plaintext_code: str,
        workspace_id,
        request=None,
    ) -> None:
        cfg = get_mfa_settings()
        from_email = cfg.get("EMAIL_FROM") or getattr(
            django_settings,
            "DEFAULT_FROM_EMAIL",
            "webmaster@localhost",
        )
        subject = "Your secure sign-in code"
        body = (
            "Use the following one-time code to complete multi-factor authentication. "
            f"Code: {plaintext_code}\n"
            f"Challenge ID: {session.id}\n"
            "If you did not request this, please ignore this message."
        )
        recipient = getattr(user, "email", None)
        if not recipient:
            raise MFAProviderError("User does not have an email address configured.")
        try:
            send_mail(subject, body, from_email, [recipient], fail_silently=False)
        except Exception as exc:  # pragma: no cover - integration specific
            raise MFAProviderError("Failed to send email OTP.") from exc

    def verify(
        self,
        *,
        user: "AbstractBaseUser",
        code: str,
        workspace_id,
        request=None,
    ) -> bool:
        """Email OTP verification is handled via hashed session storage."""
        return False
