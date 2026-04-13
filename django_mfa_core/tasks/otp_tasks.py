"""Celery task for dispatching OTP challenges."""

from __future__ import annotations

from typing import Optional
from uuid import UUID

try:  # pragma: no cover - import varies with optional dependency
    from celery import shared_task
except ImportError:  # pragma: no cover

    def shared_task(*args, **kwargs):  # type: ignore[misc]
        def decorator(func):
            return func

        if args and callable(args[0]):
            return args[0]
        return decorator


@shared_task(name="django_mfa_core.send_otp_challenge")
def send_otp_challenge_task(
    *,
    user_id: int,
    challenge_id: str,
    plaintext_code: str,
    workspace_id: Optional[str],
    provider: str,
) -> None:
    """Send an OTP using the configured provider (async path)."""
    from django.contrib.auth import get_user_model

    from django_mfa_core.models import MFASession
    from django_mfa_core.providers import build_provider_registry

    User = get_user_model()
    user = User.objects.get(pk=user_id)
    session = MFASession.objects.get(pk=UUID(challenge_id))
    ws = UUID(workspace_id) if workspace_id else None
    registry = build_provider_registry()
    instance = registry[provider]()
    instance.send_challenge(
        user=user,
        session=session,
        plaintext_code=plaintext_code,
        workspace_id=ws,
        request=None,
    )
