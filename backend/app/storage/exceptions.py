"""
Storage Provider Exception Hierarchy for CloudVault 2.0.
Provides standardized, structured error handling across all multi-cloud adapters.
"""

class StorageError(Exception):
    """Base class for all CloudVault storage provider errors."""
    def __init__(self, message: str, provider: str = "unknown", details: dict = None):
        super().__init__(message)
        self.message = message
        self.provider = provider
        self.details = details or {}

class StorageNotFoundError(StorageError, FileNotFoundError):
    """Raised when an object or bucket is not found."""
    pass

class StorageRetentionLockError(StorageError):
    """Raised when an object cannot be deleted or overwritten due to an active WORM or Object Lock retention policy."""
    pass

class StorageAuthenticationError(StorageError):
    """Raised when authentication, API key, SAS token, or IAM credentials fail."""
    pass

class StorageTimeoutError(StorageError):
    """Raised when an object transfer or health probe times out."""
    pass

class StorageIntegrityError(StorageError):
    """Raised when an object's SHA-256 or MD5 checksum fails verification."""
    pass

class StorageQuotaExceededError(StorageError):
    """Raised when cloud storage quota or disk space limit is reached."""
    pass
