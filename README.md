# django-mfa-core

Production-grade, reusable multi-factor authentication (MFA) for Django and Django REST Framework.

## Features

- **TOTP** (Google Authenticator, compatible apps) via `pyotp`
- **Email OTP** with pluggable delivery (console backend by default)
- **SMS OTP** via extensible provider base class
- **Backup codes** (hashed at rest)
- **Middleware** enforcement after login with configurable safe routes
- **DRF** serializers and views (business logic lives in services)
- **Multi-tenant ready** optional `workspace_id` on models
- **Celery-ready** OTP delivery task with synchronous fallback
- **Security**: OTP expiry, attempt limits, rate limiting (memory or Redis), encrypted device secrets, audit logging
- **Signals** after successful verification; optional QR code generation for TOTP setup

## Installation

```bash
pip install django-mfa-core
```

Optional extras:

```bash
pip install django-mfa-core[celery,redis,qr]
```

## Django setup

1. Add to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # ...
    "django_mfa_core",
]
```

2. Configure MFA (merge with your project settings):

```python
MFA_SETTINGS = {
    "ENABLED": True,
    "PROVIDERS": ["totp", "email"],
    "OTP_EXPIRY": 60,
    "MAX_ATTEMPTS": 5,
    "TRUST_DEVICE_DAYS": 7,
    "ENFORCE_MIDDLEWARE": True,
    "MIDDLEWARE_EXEMPT_PREFIXES": ["/admin/login/", "/static/", "/health/"],
    "MFA_URL_PREFIX": "/mfa/",
    "RATE_LIMIT_BACKEND": "memory",  # or "redis"
    "REDIS_URL": None,  # e.g. "redis://localhost:6379/0"
    "EMAIL_FROM": "security@example.com",
}

# Strongly recommended: dedicated Fernet key (32 url-safe base64-encoded bytes)
# from cryptography.fernet import Fernet; Fernet.generate_key()
MFA_ENCRYPTION_KEY = os.environ.get("MFA_ENCRYPTION_KEY")
```

3. Include URLs (under your API root or site URLconf):

```python
from django.urls import path, include

urlpatterns = [
    path("api/", include("django_mfa_core.api.urls")),
]
```

4. Add middleware **after** `AuthenticationMiddleware`:

```python
MIDDLEWARE = [
    # ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_mfa_core.middleware.mfa_middleware.MFAMiddleware",
]
```

5. Run migrations:

```bash
python manage.py migrate django_mfa_core
```

6. Wire Celery (optional): ensure your app imports tasks, e.g. in `AppConfig.ready()`:

```python
# your_app/apps.py
def ready(self):
    import django_mfa_core.tasks.otp_tasks  # noqa: F401
```

## Integration overview

- Users start **TOTP** enrollment with `POST /mfa/setup/` (optional `issuer`, `workspace_id`). The response includes the plaintext secret (display once), provisioning URI, and optional QR (`django-mfa-core[qr]`). Finish enrollment by posting the same path with `device_id` plus the first valid `code`.
- **Email / SMS** challenges are started with `POST /mfa/initiate/`; delivery runs via Celery when configured, otherwise synchronously.
- After login, **middleware** blocks protected routes until `POST /mfa/verify/` succeeds (or trust window is active).
- **Backup codes** can be used during verification when configured.

## API usage (DRF)

All endpoints require an authenticated user unless noted.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/mfa/initiate/` | Start email/SMS OTP challenge |
| POST | `/mfa/verify/` | Verify active challenge, TOTP, or backup code |
| POST | `/mfa/setup/` | Start TOTP enrollment **or** confirm with `device_id` + `code` |
| POST | `/mfa/disable/` | Disable MFA (requires valid code or backup code) |

Set `MFA_SETTINGS["CELERY_OTP"] = True` to deliver OTP challenges via Celery (with synchronous fallback when workers are unavailable). Configure `VERIFY_REDIRECT_URL` for HTML redirects when middleware blocks unverified sessions.

Example verify:

```http
POST /api/mfa/verify/
Content-Type: application/json

{
  "code": "123456",
  "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
  "workspace_id": null
}
```

Subscribe to signals in your project:

```python
from django.dispatch import receiver
from django_mfa_core.signals import mfa_verified

@receiver(mfa_verified)
def on_mfa_verified(sender, **kwargs):
    user = kwargs["user"]
    workspace_id = kwargs.get("workspace_id")
    ...
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
