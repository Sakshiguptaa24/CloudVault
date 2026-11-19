import os
import io
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from backend.app.storage.base import StorageProvider
from backend.app.config import settings

class AzureBlobStorageProvider(StorageProvider):
    """
    Azure Blob Storage Multi-Cloud Adapter.
    Uses azure-storage-blob client when connection string or SAS token is provided;
    falls back smoothly to simulated mode for offline and local testing.
    """

    def __init__(
        self,
        container_name: Optional[str] = None,
        connection_string: Optional[str] = None,
        simulated: bool = False
    ):
        self.container_name = container_name or getattr(settings, "AZURE_CONTAINER", "cloudvault-backups")
        self.connection_string = connection_string or getattr(settings, "AZURE_STORAGE_CONNECTION_STRING", "")
        self.simulated = simulated or not bool(self.connection_string)
        self.client = None
        self._mock_data = {}

        if not self.simulated:
            try:
                from azure.storage.blob import BlobServiceClient
                blob_service = BlobServiceClient.from_connection_string(self.connection_string)
                self.client = blob_service.get_container_client(self.container_name)
            except Exception:
                self.simulated = True

    def upload_file(self, local_path: str, destination_path: str) -> bool:
        clean_path = destination_path.lstrip("/\\").replace("\\", "/")
        if not self.simulated and self.client:
            with open(local_path, "rb") as data:
                self.client.upload_blob(name=clean_path, data=data, overwrite=True)
            return True
        with open(local_path, "rb") as f:
            self._mock_data[clean_path] = f.read()
        return True

    def upload_bytes(self, data: bytes, destination_path: str) -> bool:
        clean_path = destination_path.lstrip("/\\").replace("\\", "/")
        if not self.simulated and self.client:
            self.client.upload_blob(name=clean_path, data=data, overwrite=True)
            return True
        self._mock_data[clean_path] = data
        return True

    def download_file(self, source_path: str, local_destination_path: str) -> bool:
        clean_path = source_path.lstrip("/\\").replace("\\", "/")
        dest = Path(local_destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not self.simulated and self.client:
            stream = self.client.download_blob(clean_path)
            with open(dest, "wb") as f:
                stream.readinto(f)
            return True
        if clean_path not in self._mock_data:
            raise FileNotFoundError(f"Azure Blob not found: {source_path}")
        with open(dest, "wb") as f:
            f.write(self._mock_data[clean_path])
        return True

    def download_bytes(self, source_path: str) -> bytes:
        clean_path = source_path.lstrip("/\\").replace("\\", "/")
        if not self.simulated and self.client:
            return self.client.download_blob(clean_path).readall()
        if clean_path not in self._mock_data:
            raise FileNotFoundError(f"Azure Blob not found: {source_path}")
        return self._mock_data[clean_path]

    def delete_file(self, storage_path: str) -> bool:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        if not self.simulated and self.client:
            self.client.delete_blob(clean_path)
            return True
        if clean_path in self._mock_data:
            del self._mock_data[clean_path]
            return True
        return False

    def file_exists(self, storage_path: str) -> bool:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        if not self.simulated and self.client:
            blob = self.client.get_blob_client(clean_path)
            return blob.exists()
        return clean_path in self._mock_data

    def get_storage_name(self) -> str:
        mode = "Simulated" if self.simulated else "Connected"
        return f"Microsoft Azure Blob Storage ({mode} - {self.container_name})"

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "provider": "azure",
            "display_name": "Microsoft Azure Blob Storage",
            "features": {
                "streaming_upload": True,
                "object_versioning": True,
                "worm_retention": True,  # Immutable Blob Storage (Legal Hold / Time-based retention)
                "encryption_at_rest": True,
                "multi_cloud_replication": True,
                "lifecycle_management": True,
                "tiering": ["HOT", "COOL", "COLD", "ARCHIVE"]
            },
            "container_name": self.container_name,
            "simulated": self.simulated
        }

    def health_check(self) -> Dict[str, Any]:
        start = time.time()
        if self.simulated:
            return {
                "status": "HEALTHY",
                "provider": "azure",
                "latency_ms": round((time.time() - start) * 1000.0, 2),
                "writable": True,
                "details": f"Azure Blob Storage Adapter operational (Simulated / Ready for Azure Connection String)"
            }
        try:
            exists = self.client.exists()
            latency_ms = round((time.time() - start) * 1000.0, 2)
            return {
                "status": "HEALTHY" if exists else "DEGRADED",
                "provider": "azure",
                "latency_ms": latency_ms,
                "writable": exists,
                "details": f"Azure Container '{self.container_name}' exists: {exists}"
            }
        except Exception as e:
            return {
                "status": "UNAVAILABLE",
                "provider": "azure",
                "latency_ms": -1,
                "writable": False,
                "details": f"Azure connection failed: {str(e)}"
            }

    def get_object_metadata(self, storage_path: str) -> Dict[str, Any]:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        if not self.simulated and self.client:
            blob = self.client.get_blob_client(clean_path)
            props = blob.get_blob_properties()
            return {
                "storage_path": storage_path,
                "size_bytes": props.size,
                "content_type": props.content_settings.content_type or "application/octet-stream",
                "created_at": props.creation_time.isoformat() if props.creation_time else None,
                "modified_at": props.last_modified.isoformat() if props.last_modified else None,
                "etag": props.etag,
                "metadata": props.metadata or {}
            }
        if clean_path not in self._mock_data:
            raise FileNotFoundError(f"Azure Blob not found: {storage_path}")
        data = self._mock_data[clean_path]
        return {
            "storage_path": storage_path,
            "size_bytes": len(data),
            "content_type": "application/octet-stream",
            "created_at": datetime.utcnow().isoformat(),
            "modified_at": datetime.utcnow().isoformat(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "metadata": {"adapter": "azure_simulated"}
        }

