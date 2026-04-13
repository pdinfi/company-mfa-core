"""Enforce MFA for authenticated users until verification succeeds."""

from __future__ import annotations

from datetime import datetime
from typing import Callable
from urllib.parse import urlparse

from django.http import HttpRequest, HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from django_mfa_core.constants import SESSION_KEY_MFA_TRUST_UNTIL, SESSION_KEY_MFA_VERIFIED_AT
from django_mfa_core.models import MFADevice
from django_mfa_core.settings import get_mfa_settings


class MFAMiddleware:
    """Require MFA verification for users with active enrolled factors."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        cfg = get_mfa_settings()
        if not cfg.get("ENABLED") or not cfg.get("ENFORCE_MIDDLEWARE", True):
            return self.get_response(request)

        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return self.get_response(request)

        if not self._user_requires_mfa(user):
            return self.get_response(request)

        if self._path_is_exempt(request, cfg):
            return self.get_response(request)

        if self._session_is_trusted(request):
            return self.get_response(request)

        return self._deny(request, cfg)

    def _user_requires_mfa(self, user) -> bool:
        return MFADevice.objects.filter(user=user, is_active=True, verified=True).exists()

    def _path_is_exempt(self, request: HttpRequest, cfg: dict) -> bool:
        path = request.path or "/"
        prefixes = list(cfg.get("MIDDLEWARE_EXEMPT_PREFIXES", []))
        mfa_prefix = cfg.get("MFA_URL_PREFIX", "/mfa/")
        prefixes.append(mfa_prefix)
        return any(path.startswith(prefix) for prefix in prefixes)

    def _session_is_trusted(self, request: HttpRequest) -> bool:
        session = getattr(request, "session", None)
        if session is None:
            return False
        trust_raw = session.get(SESSION_KEY_MFA_TRUST_UNTIL)
        if trust_raw:
            trust_until = parse_datetime(trust_raw) if isinstance(trust_raw, str) else trust_raw
            if isinstance(trust_until, datetime) and timezone.is_naive(trust_until):
                trust_until = timezone.make_aware(trust_until, timezone.get_current_timezone())
            if trust_until and timezone.now() < trust_until:
                return True
        return bool(session.get(SESSION_KEY_MFA_VERIFIED_AT))

    def _deny(self, request: HttpRequest, cfg: dict) -> HttpResponse:
        accept = request.META.get("HTTP_ACCEPT", "")
        wants_json = "application/json" in accept or request.path.startswith("/api/")
        if wants_json:
            return HttpResponseForbidden("MFA verification required.")
        target = cfg.get("VERIFY_REDIRECT_URL", "/mfa/verify/")
        parsed = urlparse(target)
        if parsed.scheme:
            return HttpResponseRedirect(target)
        return HttpResponseRedirect(target)
