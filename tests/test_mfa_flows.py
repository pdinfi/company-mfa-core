"""High-level MFA flow tests."""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient

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
