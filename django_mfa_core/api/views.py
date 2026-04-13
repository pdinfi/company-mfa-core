"""Thin DRF views delegating to ``MFAService``."""

from __future__ import annotations

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from django_mfa_core.api.serializers import (
    MFADisableSerializer,
    MFAInitiateSerializer,
    MFASetupSerializer,
    MFAVerifySerializer,
)
from django_mfa_core.exceptions import MFAChallengeError, MFARateLimited, MFAVerificationError
from django_mfa_core.services.mfa_service import MFAService


class MFAInitiateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = MFAInitiateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            result = MFAService.initiate_mfa(
                request.user,
                provider=serializer.validated_data["provider"],
                request=request,
                workspace_id=serializer.validated_data.get("workspace_id"),
            )
        except (MFAChallengeError, MFARateLimited) as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(
            {
                "challenge_id": str(result.challenge_id),
                "expires_at": result.expires_at.isoformat(),
            },
            status=status.HTTP_201_CREATED,
        )


class MFAVerifyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = MFAVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            payload = MFAService.verify_mfa(
                request.user,
                serializer.validated_data["code"],
                request=request,
                workspace_id=serializer.validated_data.get("workspace_id"),
                challenge_id=serializer.validated_data.get("challenge_id"),
            )
        except MFARateLimited as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        except MFAChallengeError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except MFAVerificationError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"status": "ok", **payload}, status=status.HTTP_200_OK)


class MFASetupView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = MFASetupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        workspace_id = data.get("workspace_id")
        try:
            if data.get("device_id") and data.get("code"):
                backup = MFAService.confirm_totp(
                    request.user,
                    device_id=data["device_id"],
                    code=data["code"],
                    workspace_id=workspace_id,
                    request=request,
                )
                return Response(backup, status=status.HTTP_200_OK)
            setup = MFAService.setup_totp(
                request.user,
                issuer=data.get("issuer"),
                workspace_id=workspace_id,
                request=request,
            )
            return Response(setup, status=status.HTTP_201_CREATED)
        except (MFAChallengeError, MFAVerificationError) as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)


class MFADisableView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = MFADisableSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            MFAService.disable_mfa(
                request.user,
                code=data["code"],
                workspace_id=data.get("workspace_id"),
                challenge_id=data.get("challenge_id"),
                request=request,
            )
        except MFARateLimited as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        except (MFAChallengeError, MFAVerificationError) as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"status": "disabled"}, status=status.HTTP_200_OK)
