"""TOTP verification using pyotp."""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterable, Optional
from uuid import UUID

import pyotp
from django.db.models import Q

from django_mfa_core.constants import DEVICE_TYPE_TOTP
from django_mfa_core.models import MFADevice
from django_mfa_core.providers.base import BaseMFAProvider
from django_mfa_core.utils.encryption import decrypt_secret

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser


class TOTPMFAProvider(BaseMFAProvider):
    """Validates RFC 6238 TOTP codes against enrolled devices."""

    name = "totp"

    def send_challenge(
        self,
        *,
        user: "AbstractBaseUser",
        session,
        plaintext_code: str,
        workspace_id,
        request=None,
    ) -> None:
        """TOTP challenges are generated on the client; nothing to send."""
        return None

    def verify(
        self,
        *,
        user: "AbstractBaseUser",
        code: str,
        workspace_id,
        request=None,
    ) -> bool:
        devices = self._iter_devices(user, workspace_id)
        for device in devices:
            secret = decrypt_secret(device.secret_ciphertext)
            totp = pyotp.TOTP(secret)
            if totp.verify(code, valid_window=1):
                return True
        return False

    def _iter_devices(
        self,
        user: "AbstractBaseUser",
        workspace_id: Optional[UUID],
    ) -> Iterable[MFADevice]:
        qs = MFADevice.objects.filter(
            user=user,
            type=DEVICE_TYPE_TOTP,
            is_active=True,
            verified=True,
        )
        if workspace_id:
            qs = qs.filter(Q(workspace_id=workspace_id) | Q(workspace_id__isnull=True))
        return qs
