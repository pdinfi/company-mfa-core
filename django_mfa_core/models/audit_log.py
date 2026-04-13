"""Structured audit trail for MFA events."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models


class MFAAuditLog(models.Model):
    """Immutable audit entries for security-sensitive MFA actions."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="mfa_audit_logs",
        db_index=True,
    )
    workspace_id = models.UUIDField(null=True, blank=True, db_index=True)
    action = models.CharField(max_length=64, db_index=True)
    metadata = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        app_label = "django_mfa_core"
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["user", "action", "created_at"], name="mfa_aud_usr_act_ts"),
        ]

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"{self.action}:{self.user_id}"
