"""One-time backup codes (stored hashed)."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models


class BackupCode(models.Model):
    """Hashed backup codes for account recovery."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="mfa_backup_codes",
        db_index=True,
    )
    workspace_id = models.UUIDField(null=True, blank=True, db_index=True)
    code_hash = models.CharField(max_length=128, db_index=True)
    used_at = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "django_mfa_core"
        indexes = [
            models.Index(fields=["user", "used_at"], name="mfa_bak_usr_used"),
        ]

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"backup:{self.user_id}:{self.id}"
