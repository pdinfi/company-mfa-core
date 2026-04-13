"""MFASession tracks time-bound OTP challenges."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models

from django_mfa_core.constants import DEVICE_TYPE_CHOICES


class MFASession(models.Model):
    """Holds server-side challenge state for out-of-band OTP flows.

    The primary key UUID is the ``challenge_id`` exposed to clients.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="mfa_sessions",
        db_index=True,
    )
    workspace_id = models.UUIDField(null=True, blank=True, db_index=True)
    provider_type = models.CharField(max_length=16, choices=DEVICE_TYPE_CHOICES, db_index=True)
    expires_at = models.DateTimeField(db_index=True)
    verified = models.BooleanField(default=False, db_index=True)
    attempt_count = models.PositiveIntegerField(default=0)
    otp_salt = models.CharField(max_length=64, blank=True)
    otp_hash = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        app_label = "django_mfa_core"
        indexes = [
            models.Index(fields=["user", "verified", "expires_at"], name="mfa_sess_usr_ver_exp"),
        ]

    @property
    def challenge_id(self) -> uuid.UUID:
        """Alias for API compatibility."""
        return self.id

    def __str__(self) -> str:  # pragma: no cover - display helper
        return str(self.id)
