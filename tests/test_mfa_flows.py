"""High-level MFA flow tests."""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from django_mfa_core.exceptions import MFAChallengeError
from django_mfa_core.models import MFADevice
from django_mfa_core.services.mfa_service import MFAService

pytestmark = pytest.mark.django_db


@pytest.fixture
def user(db):
    User = get_user_model()
    return User.objects.create_user(username="alice", email="alice@example.com", password="password123")


def test_setup_and_confirm_totp(user):
    start = MFAService.setup_totp(user, issuer="TestCo")
    device = MFADevice.objects.get(id=start["device_id"])
    assert device.verified is False


def test_api_initiate_email_challenge(user):
    client = APIClient()
    client.force_authenticate(user=user)
    url = reverse("django_mfa_core:mfa-initiate")
    response = client.post(url, data={"provider": "email"}, format="json")
    assert response.status_code in (200, 201)


def test_totp_apps_single_default(user):
    apps = [{"id": "google", "issuer": "Acme Corp", "label": "Google Authenticator"}]
    with override_settings(MFA_SETTINGS={"ENABLED": True, "PROVIDERS": ["totp"], "TOTP_APPS": apps}):
        start = MFAService.setup_totp(user)
    assert start["issuer"] == "Acme Corp"
    assert start["totp_app_id"] == "google"
    dev = MFADevice.objects.get(id=start["device_id"])
    assert dev.totp_app_id == "google"
    assert dev.label == "Google Authenticator"


def test_totp_apps_multiple_requires_choice(user):
    apps = [
        {"id": "google", "issuer": "Acme", "label": "Google Authenticator"},
        {"id": "microsoft", "issuer": "Acme", "label": "Microsoft Authenticator"},
    ]
    with override_settings(MFA_SETTINGS={"ENABLED": True, "PROVIDERS": ["totp"], "TOTP_APPS": apps}):
        with pytest.raises(MFAChallengeError, match="totp_app_id"):
            MFAService.setup_totp(user)
        start = MFAService.setup_totp(user, totp_app_id="microsoft")
    assert start["totp_app_id"] == "microsoft"
    assert "Microsoft Authenticator" == MFADevice.objects.get(id=start["device_id"]).label


def test_totp_resolver_from_host(user):
    def resolver(u, *, request, totp_app_id, workspace_id):
        return {
            "issuer": f"AWS:{getattr(u, 'username', 'u')}",
            "device_label": "AWS Virtual MFA",
            "totp_app_id": "aws",
            "account_name": "arn:user:alice",
        }

    with override_settings(
        MFA_SETTINGS={"ENABLED": True, "PROVIDERS": ["totp"], "TOTP_RESOLVER": resolver},
    ):
        start = MFAService.setup_totp(user)
    assert start["issuer"].startswith("AWS:")
    assert "arn:user:alice" in start["provisioning_uri"]
    assert MFADevice.objects.get(id=start["device_id"]).label == "AWS Virtual MFA"
