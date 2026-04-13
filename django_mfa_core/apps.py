"""App configuration for django-mfa-core."""

from django.apps import AppConfig


class DjangoMfaCoreConfig(AppConfig):
    """Registers models, signals, and default checks for the MFA package."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "django_mfa_core"
    verbose_name = "Django MFA Core"

    def ready(self) -> None:
        # Import tasks so Celery autodiscover can register them when used.
        try:  # pragma: no cover - optional import path
            import django_mfa_core.tasks.otp_tasks  # noqa: F401
        except ImportError:  # pragma: no cover
            pass
        import django_mfa_core.receivers  # noqa: F401
