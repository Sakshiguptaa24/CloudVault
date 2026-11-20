import io
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Dict, Any, List, Iterator

from backend.app.storage.exceptions import (
    StorageError,
    StorageNotFoundError,
    StorageRetentionLockError,
    StorageIntegrityError
)

class StorageProvider(ABC):
    """Abstract base class for CloudVault multi-cloud storage providers."""

    @abstractmethod
    def upload_file(self, local_path: str, destination_path: str) -> bool:
        """Upload a local file to storage at destination_path."""
        pass

    @abstractmethod
    def upload_bytes(self, data: bytes, destination_path: str) -> bool:
        """Upload raw bytes to storage at destination_path."""
        pass

    @abstractmethod
    def download_file(self, source_path: str, local_destination_path: str) -> bool:
        """Download an object from storage to a local file path."""
        pass

    @abstractmethod
    def download_bytes(self, source_path: str) -> bytes:
        """Download an object from storage as raw bytes."""
        pass

    @abstractmethod
    def delete_file(self, storage_path: str) -> bool:
        """Delete an object from storage, respecting retention locks."""
        pass

    @abstractmethod
    def file_exists(self, storage_path: str) -> bool:
        """Check if an object exists in storage."""
        pass

    @abstractmethod
    def get_storage_name(self) -> str:
        """Return the friendly name of the storage provider."""
        pass

    @abstractmethod
    def get_capabilities(self) -> Dict[str, Any]:
        """Return provider capabilities (retention, streaming, tiering, encryption)."""
        pass

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Perform active connectivity and latency probe."""
        pass

    @abstractmethod
    def get_object_metadata(self, storage_path: str) -> Dict[str, Any]:
        """Retrieve object metadata (size, timestamps, etag/hash, headers)."""
        pass

    def stream_object(self, source_path: str, chunk_size: int = 65536) -> Iterator[bytes]:
        """Stream an object in fixed-size binary chunks."""
        data = self.download_bytes(source_path)
        bio = io.BytesIO(data)
        while True:
            chunk = bio.read(chunk_size)
            if not chunk:
                break
            yield chunk

    def list_objects(self, prefix: str = "") -> List[Dict[str, Any]]:
        """List objects matching a prefix."""
        return []

    def verify_object_integrity(self, storage_path: str, expected_sha256: Optional[str] = None) -> Dict[str, Any]:
        """
        Verify object existence, compute streaming SHA-256 digest, and compare against expected hash.
        Raises StorageNotFoundError if missing, or StorageIntegrityError on checksum mismatch.
        """
        if not self.file_exists(storage_path):
            raise StorageNotFoundError(f"Storage object not found: {storage_path}")

        hasher = hashlib.sha256()
        total_bytes = 0
        for chunk in self.stream_object(storage_path):
            hasher.update(chunk)
            total_bytes += len(chunk)

        computed_sha256 = hasher.hexdigest()
        is_valid = True
        if expected_sha256:
            is_valid = (computed_sha256.lower() == expected_sha256.lower())
            if not is_valid:
                raise StorageIntegrityError(
                    f"Integrity check failed for {storage_path}. "
                    f"Expected: {expected_sha256}, Computed: {computed_sha256}"
                )

        return {
            "storage_path": storage_path,
            "size_bytes": total_bytes,
            "sha256": computed_sha256,
            "expected_sha256": expected_sha256,
            "verified": is_valid
        }

    def set_retention(self, storage_path: str, retention_until: datetime, mode: str = "COMPLIANCE") -> bool:
        """Apply a WORM retention lock until a specified UTC datetime."""
        return False

    def get_retention(self, storage_path: str) -> Optional[Dict[str, Any]]:
        """Retrieve retention lock status for an object."""
        return None

    def get_uri(self, storage_path: str) -> str:
        """Return the provider-specific canonical URI (e.g. mock://, gs://, s3://, azure://)."""
        clean = storage_path.lstrip("/\\").replace("\\", "/")
        return f"storage://{clean}"
