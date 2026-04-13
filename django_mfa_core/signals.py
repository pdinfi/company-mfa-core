"""Signals emitted by django-mfa-core."""

from django.dispatch import Signal

mfa_verified = Signal()
"""Sent after successful MFA verification.

Kwargs:
    user: Authenticated user instance.
    workspace_id: Optional UUID for tenant scope.
    request: Optional HttpRequest when available.
    challenge_id: Optional UUID string for OTP challenges.
"""

mfa_challenge_sent = Signal()
"""Sent after an out-of-band challenge is dispatched (email/SMS).

Kwargs:
    user: Authenticated user instance.
    workspace_id: Optional UUID for tenant scope.
    provider: Provider name.
    challenge_id: UUID string.
"""
