"""Minimal Django settings for pytest-django and makemigrations."""

SECRET_KEY = "test-secret-key-for-django-mfa-core"
DEBUG = True
USE_TZ = True
TIME_ZONE = "UTC"
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
    "django_mfa_core",
]
MIDDLEWARE: list[str] = []
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
ROOT_URLCONF = "tests.urls"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
MFA_SETTINGS = {
    "ENABLED": True,
    "PROVIDERS": ["totp", "email", "sms"],
    "CELERY_OTP": False,
}
