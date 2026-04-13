"""Django signal receivers for MFA session hygiene."""

from __future__ import annotations

from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

from django_mfa_core.constants import SESSION_KEY_MFA_TRUST_UNTIL, SESSION_KEY_MFA_VERIFIED_AT


@receiver(user_logged_in)
def reset_mfa_session_on_login(sender, request, user, **kwargs) -> None:
    """Require a fresh MFA verification after authentication."""
    if not hasattr(request, "session"):
        return
    request.session.pop(SESSION_KEY_MFA_VERIFIED_AT, None)
    request.session.pop(SESSION_KEY_MFA_TRUST_UNTIL, None)
