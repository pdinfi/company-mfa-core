"""URL routes for MFA API endpoints."""

from django.urls import path

from django_mfa_core.api.views import MFADisableView, MFAInitiateView, MFASetupView, MFAVerifyView

app_name = "django_mfa_core"

urlpatterns = [
    path("mfa/initiate/", MFAInitiateView.as_view(), name="mfa-initiate"),
    path("mfa/verify/", MFAVerifyView.as_view(), name="mfa-verify"),
    path("mfa/setup/", MFASetupView.as_view(), name="mfa-setup"),
    path("mfa/disable/", MFADisableView.as_view(), name="mfa-disable"),
]
