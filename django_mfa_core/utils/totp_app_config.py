"""Resolve TOTP provisioning labels/issuers from host MFA_SETTINGS (no static vendor creds)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
from uuid import UUID

from django_mfa_core.constants import DEFAULT_ISSUER
from django_mfa_core.exceptions import MFAChallengeError, MFAConfigurationError


@dataclass(frozen=True)
class TOTPSetupContext:
    """Values used to build otpauth URI and MFADevice row for a pending TOTP enrollment."""

    issuer: str
    account_name: str
    device_label: str
    totp_app_id: str


def validate_totp_apps_config(apps: Any) -> None:
    """Raise MFAConfigurationError if TOTP_APPS is malformed."""
    if apps is None:
        raise MFAConfigurationError("TOTP_APPS must be a list.")
    if not isinstance(apps, list):
        raise MFAConfigurationError("TOTP_APPS must be a list.")
    seen: set[str] = set()
    for item in apps:
        if not isinstance(item, dict):
            raise MFAConfigurationError("Each TOTP_APPS entry must be a dict.")
        if "id" not in item or "issuer" not in item:
            raise MFAConfigurationError("TOTP_APPS entries require 'id' and 'issuer' keys.")
        raw_id = str(item["id"]).strip()
        if not raw_id:
            raise MFAConfigurationError("TOTP_APPS id must be non-empty.")
        if raw_id in seen:
            raise MFAConfigurationError(f"Duplicate TOTP_APPS id: {raw_id}")
        seen.add(raw_id)
        if not str(item.get("issuer", "")).strip():
            raise MFAConfigurationError(f"TOTP_APPS issuer must be non-empty for id={raw_id!r}.")


def _default_account_name(user) -> str:
    return getattr(user, "get_username", lambda: str(user.pk))()


def resolve_totp_setup_context(
    cfg: dict[str, Any],
    user,
    *,
    request,
    issuer_override: Optional[str],
    totp_app_id: Optional[str],
    workspace_id: Optional[UUID],
) -> TOTPSetupContext:
    """Pick issuer/account label from TOTP_RESOLVER, TOTP_APPS, or defaults (host-controlled)."""
    resolver = cfg.get("TOTP_RESOLVER")
    if resolver is not None:
        if not callable(resolver):
            raise MFAChallengeError("MFA TOTP_RESOLVER must be callable.")
        raw = resolver(
            user,
            request=request,
            totp_app_id=totp_app_id,
            workspace_id=workspace_id,
        )
        if not isinstance(raw, dict):
            raise MFAChallengeError("TOTP_RESOLVER must return a dict.")
        issuer = str(raw.get("issuer") or "").strip() or DEFAULT_ISSUER
        acct = raw.get("account_name")
        account_name = _default_account_name(user) if acct is None else str(acct)
        label = str(raw.get("device_label") or "Authenticator").strip() or "Authenticator"
        app_id = str(raw.get("totp_app_id") or totp_app_id or "")
        return TOTPSetupContext(
            issuer=issuer,
            account_name=account_name,
            device_label=label[:128],
            totp_app_id=app_id[:64],
        )

    ov = (issuer_override or "").strip()
    if ov:
        return TOTPSetupContext(
            issuer=ov,
            account_name=_default_account_name(user),
            device_label="Authenticator",
            totp_app_id=str(totp_app_id or "")[:64],
        )

    apps = cfg.get("TOTP_APPS") or []
    if not apps:
        di = cfg.get("TOTP_DEFAULT_ISSUER")
        if isinstance(di, str) and di.strip():
            issuer = di.strip()
        else:
            issuer = DEFAULT_ISSUER
        return TOTPSetupContext(
            issuer=issuer,
            account_name=_default_account_name(user),
            device_label="Authenticator",
            totp_app_id="",
        )

    if totp_app_id:
        pid = str(totp_app_id).strip()
        match = next((a for a in apps if str(a["id"]) == pid), None)
        if not match:
            raise MFAChallengeError("Unknown authenticator app.")
        label = match.get("label") or str(match["id"]).replace("_", " ").title()
        return TOTPSetupContext(
            issuer=str(match["issuer"]).strip(),
            account_name=_default_account_name(user),
            device_label=str(label)[:128],
            totp_app_id=pid[:64],
        )

    if len(apps) == 1:
        a = apps[0]
        label = a.get("label") or str(a["id"]).replace("_", " ").title()
        return TOTPSetupContext(
            issuer=str(a["issuer"]).strip(),
            account_name=_default_account_name(user),
            device_label=str(label)[:128],
            totp_app_id=str(a["id"])[:64],
        )

    raise MFAChallengeError(
        "totp_app_id is required when multiple authenticator apps are configured.",
    )
