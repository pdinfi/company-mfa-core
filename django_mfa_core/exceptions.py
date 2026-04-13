"""Domain-specific exceptions for MFA flows."""


class MFAError(Exception):
    """Base class for MFA errors."""


class MFAConfigurationError(MFAError):
    """Raised when package or project settings are invalid."""


class MFARateLimited(MFAError):
    """Raised when a user exceeds OTP initiation or verification rate limits."""


class MFAChallengeError(MFAError):
    """Raised when a challenge is missing, expired, or exhausted."""


class MFAVerificationError(MFAError):
    """Raised when a code cannot be verified."""


class MFAProviderError(MFAError):
    """Raised when a provider fails to deliver or process a challenge."""
