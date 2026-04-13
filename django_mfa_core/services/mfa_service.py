"""Core orchestration for MFA flows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, Optional
from uuid import UUID

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from django_mfa_core.constants import (
    AUDIT_ACTION_BACKUP_USED,
    AUDIT_ACTION_CHALLENGE_CREATED,
    AUDIT_ACTION_CHALLENGE_FAILED,
    AUDIT_ACTION_CHALLENGE_VERIFIED,
    AUDIT_ACTION_DEVICE_DISABLED,
    AUDIT_ACTION_DEVICE_ENABLED,
    DEVICE_TYPE_EMAIL,
    DEVICE_TYPE_SMS,
    DEVICE_TYPE_TOTP,
    SESSION_KEY_MFA_TRUST_UNTIL,
    SESSION_KEY_MFA_VERIFIED_AT,
)
from django_mfa_core.exceptions import (
    MFAChallengeError,
    MFARateLimited,
    MFAVerificationError,
)
from django_mfa_core.models import BackupCode, MFAAuditLog, MFADevice, MFASession
from django_mfa_core.providers import build_provider_registry
from django_mfa_core.services import otp_service
from django_mfa_core.services import totp_service
from django_mfa_core.settings import get_mfa_settings
from django_mfa_core.signals import mfa_challenge_sent, mfa_verified
from django_mfa_core.utils.encryption import decrypt_secret, encrypt_secret, hash_backup_code
from django_mfa_core.utils.helpers import get_client_ip, normalize_workspace_id
from django_mfa_core.utils.rate_limit import rate_limit


@dataclass
class MFAInitiateResult:
    """Structured response for OTP initiation."""

    challenge_id: UUID
    expires_at: timezone.datetime


class MFAService:
    """Facade exposing all MFA operations used by APIs and middleware."""

    @staticmethod
    def _audit(
        *,
        user,
        action: str,
        request=None,
        workspace_id: Optional[UUID] = None,
        metadata: Optional[dict] = None,
    ) -> None:
        MFAAuditLog.objects.create(
            user=user,
            workspace_id=workspace_id,
            action=action,
            metadata=metadata or {},
            ip_address=get_client_ip(request) if request else None,
            user_agent=(request.META.get("HTTP_USER_AGENT", "") if request else "")[:1024],
        )

    @classmethod
    def initiate_mfa(
        cls,
        user,
        *,
        provider: str,
        request=None,
        workspace_id: Optional[UUID | str] = None,
    ) -> MFAInitiateResult:
        """Create a challenge and dispatch an out-of-band OTP when applicable."""
        cfg = get_mfa_settings()
        if not cfg.get("ENABLED", True):
            raise MFAChallengeError("MFA is disabled.")
        ws = normalize_workspace_id(workspace_id)
        rl = rate_limit(f"initiate:{user.pk}:{ws or 'global'}", cfg.get("INITIATE_RATE_LIMIT", "5/m"))
        if not rl.allowed:
            raise MFARateLimited("Too many MFA challenges requested.")

        registry = build_provider_registry()
        if provider not in registry:
            raise MFAChallengeError(f"Unknown provider '{provider}'.")
        if provider not in cfg.get("PROVIDERS", []):
            raise MFAChallengeError(f"Provider '{provider}' is not enabled.")

        if provider not in (DEVICE_TYPE_EMAIL, DEVICE_TYPE_SMS):
            raise MFAChallengeError("initiate_mfa is only valid for email or SMS providers.")

        code = otp_service.mint_numeric_otp()
        expires = timezone.now() + timedelta(seconds=int(cfg.get("OTP_EXPIRY", 60)))
        session = MFASession.objects.create(
            user=user,
            workspace_id=ws,
            provider_type=provider,
            expires_at=expires,
        )
        otp_service.attach_otp_to_session(session, code)

        provider_cls = registry[provider]
        instance = provider_cls()
        queued = False
        if cfg.get("CELERY_OTP"):
            queued = cls._dispatch_async_otp_task(
                user.pk,
                str(session.id),
                code,
                ws,
                provider=provider,
            )
        if not queued:
            instance.send_challenge(
                user=user,
                session=session,
                plaintext_code=code,
                workspace_id=ws,
                request=request,
            )

        cls._audit(
            user=user,
            action=AUDIT_ACTION_CHALLENGE_CREATED,
            request=request,
            workspace_id=ws,
            metadata={"provider": provider, "challenge_id": str(session.id)},
        )
        mfa_challenge_sent.send(
            sender=MFAService,
            user=user,
            workspace_id=ws,
            provider=provider,
            challenge_id=str(session.id),
        )

        return MFAInitiateResult(challenge_id=session.id, expires_at=expires)

    @classmethod
    def _dispatch_async_otp_task(
        cls,
        user_id: int,
        challenge_id: str,
        code: str,
        workspace_id: Optional[UUID],
        *,
        provider: str,
    ) -> bool:
        """Queue Celery delivery when configured; falls back to sync if unavailable."""
        try:
            from django_mfa_core.tasks.otp_tasks import send_otp_challenge_task
        except Exception:  # pragma: no cover - optional Celery wiring
            return False
        send = getattr(send_otp_challenge_task, "delay", None)
        if not callable(send):
            return False
        send(
            user_id=user_id,
            challenge_id=challenge_id,
            plaintext_code=code,
            workspace_id=str(workspace_id) if workspace_id else None,
            provider=provider,
        )
        return True

    @classmethod
    def verify_mfa(
        cls,
        user,
        code: str,
        *,
        request=None,
        workspace_id: Optional[UUID | str] = None,
        challenge_id: Optional[UUID | str] = None,
    ) -> Dict[str, Any]:
        """Verify OTP/TOTP/backup codes and mark the Django session trusted."""
        cfg = get_mfa_settings()
        if not cfg.get("ENABLED", True):
            raise MFAChallengeError("MFA is disabled.")
        ws = normalize_workspace_id(workspace_id)
        rl = rate_limit(f"verify:{user.pk}:{ws or 'global'}", cfg.get("VERIFY_RATE_LIMIT", "30/m"))
        if not rl.allowed:
            raise MFARateLimited("Too many verification attempts.")

        if challenge_id:
            with transaction.atomic():
                return cls._verify_challenge(user, code, challenge_id=challenge_id, request=request, workspace_id=ws)

        if cls._verify_totp(user, code, workspace_id=ws, request=request):
            cls._mark_success(user, request=request, workspace_id=ws)
            return {"method": "totp"}

        if cls._verify_backup(user, code, workspace_id=ws, request=request):
            cls._mark_success(user, request=request, workspace_id=ws)
            return {"method": "backup"}

        cls._audit(
            user=user,
            action=AUDIT_ACTION_CHALLENGE_FAILED,
            request=request,
            workspace_id=ws,
            metadata={"reason": "invalid_code"},
        )
        raise MFAVerificationError("Invalid verification code.")

    @classmethod
    def _verify_challenge(
        cls,
        user,
        code: str,
        *,
        challenge_id: UUID | str,
        request=None,
        workspace_id: Optional[UUID],
    ) -> Dict[str, Any]:
        try:
            challenge_uuid = UUID(str(challenge_id))
        except ValueError as exc:
            raise MFAChallengeError("Invalid challenge identifier.") from exc

        session = (
            MFASession.objects.select_for_update()
            .filter(id=challenge_uuid, user=user, verified=False)
            .first()
        )
        if not session:
            raise MFAChallengeError("Challenge not found or already completed.")

        if otp_service.is_session_expired(session):
            raise MFAChallengeError("Challenge has expired.")

        cfg = get_mfa_settings()
        max_attempts = int(cfg.get("MAX_ATTEMPTS", 5))
        if session.attempt_count >= max_attempts:
            raise MFAChallengeError("Maximum verification attempts exceeded.")

        session.attempt_count += 1
        session.save(update_fields=["attempt_count"])

        if not otp_service.session_otp_matches(session, code):
            cls._audit(
                user=user,
                action=AUDIT_ACTION_CHALLENGE_FAILED,
                request=request,
                workspace_id=workspace_id,
                metadata={"challenge_id": str(session.id)},
            )
            raise MFAVerificationError("Invalid verification code.")

        session.verified = True
        session.save(update_fields=["verified"])
        cls._audit(
            user=user,
            action=AUDIT_ACTION_CHALLENGE_VERIFIED,
            request=request,
            workspace_id=workspace_id,
            metadata={"challenge_id": str(session.id), "provider": session.provider_type},
        )
        cls._mark_success(user, request=request, workspace_id=workspace_id, challenge_id=session.id)
        return {"method": session.provider_type, "challenge_id": str(session.id)}

    @classmethod
    def _verify_totp(cls, user, code: str, *, workspace_id: Optional[UUID], request=None) -> bool:
        registry = build_provider_registry()
        provider = registry[DEVICE_TYPE_TOTP]()
        ok = provider.verify(user=user, code=code, workspace_id=workspace_id, request=request)
        if ok:
            cls._audit(
                user=user,
                action=AUDIT_ACTION_CHALLENGE_VERIFIED,
                request=request,
                workspace_id=workspace_id,
                metadata={"method": "totp"},
            )
        return ok

    @classmethod
    def _verify_backup(cls, user, code: str, *, workspace_id: Optional[UUID], request=None) -> bool:
        digest = hash_backup_code(code)
        with transaction.atomic():
            qs = BackupCode.objects.select_for_update().filter(user=user, used_at__isnull=True, code_hash=digest)
            if workspace_id:
                qs = qs.filter(Q(workspace_id=workspace_id) | Q(workspace_id__isnull=True))
            record = qs.first()
            if not record:
                return False
            record.used_at = timezone.now()
            record.save(update_fields=["used_at"])
        cls._audit(
            user=user,
            action=AUDIT_ACTION_BACKUP_USED,
            request=request,
            workspace_id=workspace_id,
            metadata={"backup_id": str(record.id)},
        )
        return True

    @classmethod
    def _mark_success(cls, user, *, request, workspace_id: Optional[UUID], challenge_id: Optional[UUID] = None) -> None:
        if request and hasattr(request, "session"):
            request.session[SESSION_KEY_MFA_VERIFIED_AT] = timezone.now().isoformat()
            cfg = get_mfa_settings()
            trust_days = int(cfg.get("TRUST_DEVICE_DAYS", 0) or 0)
            if trust_days > 0:
                trust_until = timezone.now() + timedelta(days=trust_days)
                request.session[SESSION_KEY_MFA_TRUST_UNTIL] = trust_until.isoformat()
        mfa_verified.send(
            sender=MFAService,
            user=user,
            workspace_id=workspace_id,
            request=request,
            challenge_id=str(challenge_id) if challenge_id else None,
        )

    @classmethod
    def enable_mfa(cls, user, *, provider: str, workspace_id: Optional[UUID | str] = None, request=None) -> MFADevice:
        """Activate a channel-based factor such as email or SMS."""
        cfg = get_mfa_settings()
        if not cfg.get("ENABLED", True):
            raise MFAChallengeError("MFA is disabled.")
        if provider not in (DEVICE_TYPE_EMAIL, DEVICE_TYPE_SMS):
            raise MFAChallengeError("enable_mfa supports email or SMS enrollment only.")
        ws = normalize_workspace_id(workspace_id)
        device, _created = MFADevice.objects.update_or_create(
            user=user,
            type=provider,
            workspace_id=ws,
            defaults={
                "secret_ciphertext": "",
                "verified": True,
                "is_active": True,
                "label": provider.upper(),
            },
        )
        cls._audit(
            user=user,
            action=AUDIT_ACTION_DEVICE_ENABLED,
            request=request,
            workspace_id=ws,
            metadata={"type": provider},
        )
        return device

    @classmethod
    def disable_mfa(
        cls,
        user,
        *,
        code: str,
        workspace_id: Optional[UUID | str] = None,
        request=None,
        challenge_id: Optional[UUID | str] = None,
    ) -> None:
        """Disable all MFA factors after a successful verification."""
        ws = normalize_workspace_id(workspace_id)
        try:
            cls.verify_mfa(
                user,
                code,
                request=request,
                workspace_id=ws,
                challenge_id=challenge_id,
            )
        except MFAVerificationError as exc:
            raise MFAVerificationError("Valid MFA code required to disable MFA.") from exc

        with transaction.atomic():
            MFADevice.objects.filter(user=user).update(is_active=False, verified=False)
            BackupCode.objects.filter(user=user).delete()
            MFASession.objects.filter(user=user, verified=False).delete()

        if request and hasattr(request, "session"):
            request.session.pop(SESSION_KEY_MFA_VERIFIED_AT, None)
            request.session.pop(SESSION_KEY_MFA_TRUST_UNTIL, None)

        cls._audit(
            user=user,
            action=AUDIT_ACTION_DEVICE_DISABLED,
            request=request,
            workspace_id=ws,
            metadata={"scope": "all_devices"},
        )

    @classmethod
    def setup_totp(
        cls,
        user,
        *,
        issuer: Optional[str] = None,
        workspace_id: Optional[UUID | str] = None,
        request=None,
    ) -> Dict[str, Any]:
        """Create a pending TOTP device and return provisioning details."""
        cfg = get_mfa_settings()
        if DEVICE_TYPE_TOTP not in cfg.get("PROVIDERS", []):
            raise MFAChallengeError("TOTP provider is disabled.")
        ws = normalize_workspace_id(workspace_id)
        secret = totp_service.generate_totp_secret()
        ciphertext = encrypt_secret(secret)
        device = MFADevice.objects.create(
            user=user,
            workspace_id=ws,
            type=DEVICE_TYPE_TOTP,
            secret_ciphertext=ciphertext,
            verified=False,
            is_active=True,
            label="Authenticator",
        )
        account_name = getattr(user, "get_username", lambda: str(user.pk))()
        uri = totp_service.build_provisioning_uri(secret, account_name, issuer=issuer)
        payload: Dict[str, Any] = {
            "device_id": str(device.id),
            "secret": secret,
            "provisioning_uri": uri,
        }
        qr = totp_service.render_qr_code_base64(uri)
        if qr:
            payload["qr_code_data_url"] = qr
        cls._audit(
            user=user,
            action=AUDIT_ACTION_DEVICE_ENABLED,
            request=request,
            workspace_id=ws,
            metadata={"stage": "totp_pending", "device_id": str(device.id)},
        )
        return payload

    @classmethod
    def confirm_totp(
        cls,
        user,
        *,
        device_id: UUID | str,
        code: str,
        workspace_id: Optional[UUID | str] = None,
        request=None,
    ) -> Dict[str, Any]:
        """Confirm a pending TOTP enrollment and optionally generate backup codes."""
        ws = normalize_workspace_id(workspace_id)
        device = MFADevice.objects.filter(
            id=device_id,
            user=user,
            type=DEVICE_TYPE_TOTP,
            verified=False,
            is_active=True,
        ).first()
        if not device:
            raise MFAChallengeError("Unknown or already verified device.")

        secret = decrypt_secret(device.secret_ciphertext)
        if not totp_service.verify_totp(secret, code):
            raise MFAVerificationError("Invalid TOTP code.")

        device.verified = True
        device.save()

        cfg = get_mfa_settings()
        codes = cls._generate_backup_codes(user, workspace_id=ws, count=int(cfg.get("BACKUP_CODE_COUNT", 10)))
        cls._audit(
            user=user,
            action=AUDIT_ACTION_DEVICE_ENABLED,
            request=request,
            workspace_id=ws,
            metadata={"stage": "totp_confirmed", "device_id": str(device.id)},
        )
        return {"backup_codes": codes}

    @classmethod
    def _generate_backup_codes(cls, user, *, workspace_id: Optional[UUID], count: int) -> list[str]:
        """Create human-readable backup codes and persist hashed values."""
        import secrets
        import string

        alphabet = string.ascii_uppercase + string.digits
        raw_codes: list[str] = []
        for _ in range(count):
            token = "".join(secrets.choice(alphabet) for _ in range(10))
            raw_codes.append(f"{token[:5]}-{token[5:]}")
        BackupCode.objects.filter(user=user, workspace_id=workspace_id, used_at__isnull=True).delete()
        BackupCode.objects.bulk_create(
            [
                BackupCode(
                    user=user,
                    workspace_id=workspace_id,
                    code_hash=hash_backup_code(code),
                )
                for code in raw_codes
            ]
        )
        return raw_codes
