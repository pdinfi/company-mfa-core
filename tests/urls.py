"""URLConf for tests."""

from django.urls import include, path

urlpatterns = [
    path("", include("django_mfa_core.api.urls")),
]
