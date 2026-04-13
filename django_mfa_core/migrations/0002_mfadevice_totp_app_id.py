# Generated manually for django-mfa-core

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("django_mfa_core", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="mfadevice",
            name="totp_app_id",
            field=models.CharField(
                blank=True,
                help_text="Host-defined authenticator preset id (e.g. google, microsoft) when using TOTP_APPS.",
                max_length=64,
            ),
        ),
    ]
