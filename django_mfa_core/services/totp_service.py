"""TOTP-specific helpers built on pyotp."""

from __future__ import annotations

from typing import Optional

import pyotp

from django_mfa_core.constants import DEFAULT_ISSUER


def generate_totp_secret() -> str:
    """Return a new base32-encoded TOTP secret."""
    return pyotp.random_base32()


def build_provisioning_uri(
    secret: str,
    account_name: str,
    *,
    issuer: Optional[str] = None,
) -> str:
    """Build an ``otpauth://`` URI suitable for authenticator apps."""
    label = account_name
    return pyotp.totp.TOTP(secret).provisioning_uri(name=label, issuer_name=issuer or DEFAULT_ISSUER)


def verify_totp(secret: str, code: str, *, valid_window: int = 1) -> bool:
    """Verify a TOTP code for a decrypted secret."""
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(code, valid_window=valid_window))


def render_qr_code_base64(uri: str) -> Optional[str]:
    """Return a PNG data URL for the provisioning URI when qrcode is installed."""
    try:
        import qrcode
        from io import BytesIO
        import base64
    except ImportError:  # pragma: no cover - optional dependency
        return None
    img = qrcode.make(uri)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"
