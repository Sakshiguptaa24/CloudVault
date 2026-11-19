import os
import io
import json
import time
from pathlib import Path
from typing import Dict, Any
from backend.app.storage.base import StorageProvider
from backend.app.config import settings

class GCSStorageProvider(StorageProvider):
    """Google Cloud Storage Provider using official google-cloud-storage library."""

    def __init__(self, bucket_name: str = None, credentials_path: str = None):
        self.bucket_name = bucket_name or settings.GCS_BUCKET_NAME
        self.credentials_path = credentials_path or settings.GOOGLE_APPLICATION_CREDENTIALS

        try:
            from google.cloud import storage
            from google.oauth2 import service_account

            # 1. Inline JSON credentials (common for Cloud Run / Render / PaaS)
            if getattr(settings, "GCS_CREDENTIALS_JSON", None) and settings.GCS_CREDENTIALS_JSON.strip():
                try:
                    creds_dict = json.loads(settings.GCS_CREDENTIALS_JSON)
                    creds = service_account.Credentials.from_service_account_info(creds_dict)
                    self.client = storage.Client(credentials=creds, project=creds_dict.get("project_id") or settings.GCS_PROJECT_ID or None)
                except Exception as json_err:
                    raise ValueError(f"Invalid GCS_CREDENTIALS_JSON string: {json_err}")
            # 2. File-path based credentials
            elif self.credentials_path and os.path.exists(self.credentials_path):
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.credentials_path
                self.client = storage.Client(project=settings.GCS_PROJECT_ID or None)
            # 3. Environment default credentials (e.g. running directly on Cloud Run / GCE)
            else:
                self.client = storage.Client(project=settings.GCS_PROJECT_ID or None)

            self.bucket = self.client.bucket(self.bucket_name)
        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize Google Cloud Storage Client: {str(e)}. "
                "Ensure GOOGLE_APPLICATION_CREDENTIALS or GCS_CREDENTIALS_JSON is configured with valid GCP service account credentials, "
                "or set STORAGE_PROVIDER=mock in .env to use local mock storage."
            )

    def _get_blob(self, storage_path: str):
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        return self.bucket.blob(clean_path)

    def upload_file(self, local_path: str, destination_path: str) -> bool:
        blob = self._get_blob(destination_path)
        blob.upload_from_filename(local_path)
        return True

    def upload_bytes(self, data: bytes, destination_path: str) -> bool:
        blob = self._get_blob(destination_path)
        blob.upload_from_string(data)
        return True

    def download_file(self, source_path: str, local_destination_path: str) -> bool:
        blob = self._get_blob(source_path)
        if not blob.exists():
            raise FileNotFoundError(f"GCS Object not found: {source_path}")
        dest = Path(local_destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        blob.download_to_filename(str(dest))
        return True

    def download_bytes(self, source_path: str) -> bytes:
        blob = self._get_blob(source_path)
        if not blob.exists():
            raise FileNotFoundError(f"GCS Object not found: {source_path}")
        return blob.download_as_bytes()

    def delete_file(self, storage_path: str) -> bool:
        blob = self._get_blob(storage_path)
        if blob.exists():
            blob.delete()
            return True
        return False

    def file_exists(self, storage_path: str) -> bool:
        blob = self._get_blob(storage_path)
        return blob.exists()

    def get_storage_name(self) -> str:
        return f"Google Cloud Storage (gs://{self.bucket_name})"

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "provider": "gcs",
            "display_name": f"Google Cloud Storage (gs://{self.bucket_name})",
            "features": {
                "streaming_upload": True,
                "object_versioning": True,
                "worm_retention": True,
                "encryption_at_rest": True,
                "multi_cloud_replication": True,
                "lifecycle_management": True,
                "tiering": ["STANDARD", "NEARLINE", "COLDLINE", "ARCHIVE"]
            },
            "bucket_name": self.bucket_name,
            "simulated": False
        }

    def health_check(self) -> Dict[str, Any]:
        start = time.time()
        try:
            exists = self.bucket.exists()
            latency_ms = round((time.time() - start) * 1000.0, 2)
            if exists:
                return {
                    "status": "HEALTHY",
                    "provider": "gcs",
                    "latency_ms": latency_ms,
                    "writable": True,
                    "details": f"Connected to GCS bucket gs://{self.bucket_name}"
                }
            else:
                return {
                    "status": "DEGRADED",
                    "provider": "gcs",
                    "latency_ms": latency_ms,
                    "writable": False,
                    "details": f"Bucket gs://{self.bucket_name} does not exist"
                }
        except Exception as e:
            return {
                "status": "UNAVAILABLE",
                "provider": "gcs",
                "latency_ms": -1,
                "writable": False,
                "details": f"GCS connection error: {str(e)}"
            }

    def get_object_metadata(self, storage_path: str) -> Dict[str, Any]:
        blob = self._get_blob(storage_path)
        if not blob.exists():
            raise FileNotFoundError(f"GCS Object not found: {storage_path}")
        blob.reload()
        return {
            "storage_path": storage_path,
            "size_bytes": blob.size,
            "content_type": blob.content_type or "application/octet-stream",
            "created_at": blob.time_created.isoformat() if blob.time_created else None,
            "modified_at": blob.updated.isoformat() if blob.updated else None,
            "md5_or_hash": blob.md5_hash,
            "metadata": blob.metadata or {}
        }
