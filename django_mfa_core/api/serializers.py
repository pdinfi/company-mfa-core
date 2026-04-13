"""Serializers for MFA API endpoints."""

from __future__ import annotations

from typing import Any, Dict

from rest_framework import serializers


class MFAInitiateSerializer(serializers.Serializer):
    """Start an email/SMS OTP challenge."""

    provider = serializers.ChoiceField(choices=["email", "sms"])
    workspace_id = serializers.UUIDField(required=False, allow_null=True)


class MFAVerifySerializer(serializers.Serializer):
    """Verify OTP/TOTP/backup codes."""

    code = serializers.CharField(max_length=32, trim_whitespace=True)
    challenge_id = serializers.UUIDField(required=False, allow_null=True)
    workspace_id = serializers.UUIDField(required=False, allow_null=True)


class MFASetupSerializer(serializers.Serializer):
    """Begin TOTP enrollment or confirm a pending device."""

    issuer = serializers.CharField(required=False, allow_blank=True)
    totp_app_id = serializers.CharField(required=False, allow_blank=True, max_length=64)
    workspace_id = serializers.UUIDField(required=False, allow_null=True)
    device_id = serializers.UUIDField(required=False, allow_null=True)
    code = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        device_id = attrs.get("device_id")
        code = attrs.get("code")
        if (device_id and not code) or (code and not device_id):
            raise serializers.ValidationError("device_id and code must be provided together.")
        return attrs


class MFADisableSerializer(serializers.Serializer):
    """Disable MFA after presenting a valid factor."""

    code = serializers.CharField(max_length=32)
    workspace_id = serializers.UUIDField(required=False, allow_null=True)
    challenge_id = serializers.UUIDField(required=False, allow_null=True)
