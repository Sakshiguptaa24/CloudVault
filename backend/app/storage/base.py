from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

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
        """Delete an object from storage."""
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
