"""MFADevice stores enrolled second factors per user (and optional workspace)."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models

from django_mfa_core.constants import DEVICE_TYPE_CHOICES


class MFADevice(models.Model):
    """Represents an enrolled MFA device (TOTP, email channel, SMS channel)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="mfa_devices",
        db_index=True,
    )
    workspace_id = models.UUIDField(
        null=True,
        blank=True,
        db_index=True,
        help_text="Optional tenant/workspace scope; extend via proxy models if needed.",
    )
    type = models.CharField(max_length=16, choices=DEVICE_TYPE_CHOICES, db_index=True)
    secret_ciphertext = models.TextField(
        blank=True,
        help_text="Fernet-encrypted secret for TOTP; empty for channel-based factors.",
    )
    verified = models.BooleanField(default=False, db_index=True)
    is_active = models.BooleanField(default=True, db_index=True)
    label = models.CharField(max_length=128, blank=True)
    totp_app_id = models.CharField(
        max_length=64,
        blank=True,
        help_text="Host-defined authenticator preset id (e.g. google, microsoft) when using TOTP_APPS.",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "django_mfa_core"
        indexes = [
            models.Index(fields=["user", "is_active", "verified"], name="mfa_dev_usr_act_v"),
            models.Index(fields=["workspace_id", "user"], name="mfa_dev_ws_usr"),
        ]

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"{self.user_id}:{self.type}:{self.id}"
