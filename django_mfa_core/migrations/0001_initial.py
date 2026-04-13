# Generated manually for django-mfa-core

import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="MFADevice",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("workspace_id", models.UUIDField(blank=True, db_index=True, null=True)),
                (
                    "type",
                    models.CharField(
                        choices=[("totp", "TOTP"), ("email", "Email OTP"), ("sms", "SMS OTP")],
                        db_index=True,
                        max_length=16,
                    ),
                ),
                (
                    "secret_ciphertext",
                    models.TextField(
                        blank=True,
                        help_text="Fernet-encrypted secret for TOTP; empty for channel-based factors.",
                    ),
                ),
                ("verified", models.BooleanField(db_index=True, default=False)),
                ("is_active", models.BooleanField(db_index=True, default=True)),
                ("label", models.CharField(blank=True, max_length=128)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="mfa_devices",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="MFASession",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("workspace_id", models.UUIDField(blank=True, db_index=True, null=True)),
                (
                    "provider_type",
                    models.CharField(
                        choices=[("totp", "TOTP"), ("email", "Email OTP"), ("sms", "SMS OTP")],
                        db_index=True,
                        max_length=16,
                    ),
                ),
                ("expires_at", models.DateTimeField(db_index=True)),
                ("verified", models.BooleanField(db_index=True, default=False)),
                ("attempt_count", models.PositiveIntegerField(default=0)),
                ("otp_salt", models.CharField(blank=True, max_length=64)),
                ("otp_hash", models.CharField(blank=True, max_length=128)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="mfa_sessions",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="BackupCode",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("workspace_id", models.UUIDField(blank=True, db_index=True, null=True)),
                ("code_hash", models.CharField(db_index=True, max_length=128)),
                ("used_at", models.DateTimeField(blank=True, db_index=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="mfa_backup_codes",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="MFAAuditLog",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("workspace_id", models.UUIDField(blank=True, db_index=True, null=True)),
                ("action", models.CharField(db_index=True, max_length=64)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="mfa_audit_logs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ("-created_at",),
            },
        ),
        migrations.AddIndex(
            model_name="mfadevice",
            index=models.Index(fields=["user", "is_active", "verified"], name="mfa_dev_usr_act_v"),
        ),
        migrations.AddIndex(
            model_name="mfadevice",
            index=models.Index(fields=["workspace_id", "user"], name="mfa_dev_ws_usr"),
        ),
        migrations.AddIndex(
            model_name="mfasession",
            index=models.Index(fields=["user", "verified", "expires_at"], name="mfa_sess_usr_ver_exp"),
        ),
        migrations.AddIndex(
            model_name="backupcode",
            index=models.Index(fields=["user", "used_at"], name="mfa_bak_usr_used"),
        ),
        migrations.AddIndex(
            model_name="mfaauditlog",
            index=models.Index(fields=["user", "action", "created_at"], name="mfa_aud_usr_act_ts"),
        ),
    ]
