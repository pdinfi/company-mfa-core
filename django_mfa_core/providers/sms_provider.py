"""SMS delivery stub with a clear extension point for real gateways."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django_mfa_core.exceptions import MFAProviderError
from django_mfa_core.providers.base import BaseMFAProvider

if TYPE_CHECKING:
    from django_mfa_core.models import MFASession

    from django.contrib.auth.models import AbstractBaseUser

logger = logging.getLogger(__name__)


class SMSMFAProvider(BaseMFAProvider):
    """Placeholder SMS provider; subclass and override ``send_challenge``."""

    name = "sms"

    def send_challenge(
        self,
        *,
        user: "AbstractBaseUser",
        session: "MFASession",
        plaintext_code: str,
        workspace_id,
        request=None,
    ) -> None:
        phone = getattr(user, "phone_number", None) or getattr(user, "phone", None)
        if not phone:
            raise MFAProviderError(
                "SMS MFA requires a user phone field; extend this provider for your user model.",
            )
        logger.warning(
            "SMS MFA provider using console fallback for user_id=%s challenge=%s code=%s",
            getattr(user, "pk", None),
            session.id,
            plaintext_code,
        )

    def verify(
        self,
        *,
        user: "AbstractBaseUser",
        code: str,
        workspace_id,
        request=None,
    ) -> bool:
        return False
