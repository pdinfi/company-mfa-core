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

This package does **not** load `.env` files. In the **project that installs** `django-mfa-core`, put secrets and integration settings in **your** `.env`, load them in `settings.py`, and pass them into Django and `MFA_SETTINGS`. See **`.env.example`** in this repo for a full template.

| Factor | Comes from the **user row** (your DB) | Comes from **your** `.env` / `settings.py` |
|--------|----------------------------------------|--------------------------------------------|
| **Authenticator (TOTP)** | Account label in the URI (e.g. username); enrolled secret is stored encrypted on `MFADevice`, verified with `pyotp` | `MFA_ENCRYPTION_KEY`; issuer / `TOTP_APPS` / `TOTP_DEFAULT_ISSUER` / `TOTP_RESOLVER` (e.g. `MFA_TOTP_ISSUER`) |
| **Email OTP** | **`user.email`** (To) | SMTP or mail API (`EMAIL_*`, `DEFAULT_FROM_EMAIL`); optional `MFA_SETTINGS["EMAIL_FROM"]` (e.g. `MFA_EMAIL_FROM`) |
| **SMS OTP** | **`user.phone`** or **`user.phone_number`** (To) | Gateway credentials in **your** `.env`, read by **your** `SMSMFAProvider` subclass ([Plivo](https://www.plivo.com), Twilio, Vonage, AWS SNS, etc. — see `.env.example`) |

1. Add to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # ...
    "django_mfa_core",
]
```

2. Configure MFA (merge with your project settings):

```python
import os

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
    "REDIS_URL": os.environ.get("REDIS_URL"),  # if using redis rate limiter
    "EMAIL_FROM": os.environ.get("MFA_EMAIL_FROM", "security@example.com"),
    # Optional: authenticator-app presets (Google / Microsoft / AWS Virtual MFA are all standard TOTP).
    # Build this dict from your own settings/env — nothing is hardcoded in the package.
    "TOTP_APPS": [
        {"id": "google", "issuer": os.environ.get("MFA_TOTP_ISSUER", "My Company"), "label": "Google Authenticator"},
        {"id": "microsoft", "issuer": os.environ.get("MFA_TOTP_ISSUER", "My Company"), "label": "Microsoft Authenticator"},
    ],
    # Or omit TOTP_APPS and set a single default issuer:
    # "TOTP_DEFAULT_ISSUER": os.environ.get("MFA_TOTP_ISSUER"),
    # Full control: callable(user, request, totp_app_id, workspace_id) -> dict with issuer, account_name?, device_label?, totp_app_id?
    # "TOTP_RESOLVER": my_totp_resolver,
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

- Users start **TOTP** enrollment with `POST /mfa/setup/` (optional `issuer`, `totp_app_id`, `workspace_id`). If you configure multiple `TOTP_APPS`, clients must pass `totp_app_id` (unless only one app is listed). The response includes the plaintext secret (display once), provisioning URI, resolved `issuer`, optional `totp_app_id`, and optional QR (`django-mfa-core[qr]`). Finish enrollment by posting the same path with `device_id` plus the first valid `code`.
- **Email / SMS** challenges are started with `POST /mfa/initiate/`; delivery runs via Celery when configured, otherwise synchronously.
- After login, **middleware** blocks protected routes until `POST /mfa/verify/` succeeds (or trust window is active).
- **Backup codes** can be used during verification when configured.

## API usage (DRF)

All endpoints require an authenticated user unless noted.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/mfa/initiate/` | Start email/SMS OTP challenge |
| POST | `/mfa/verify/` | Verify active challenge, TOTP, or backup code |
| POST | `/mfa/setup/` | Start TOTP enrollment (`issuer`, `totp_app_id`) **or** confirm with `device_id` + `code` |
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
