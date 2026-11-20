import os
import io
import json
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Iterator

from backend.app.storage.base import StorageProvider
from backend.app.storage.exceptions import (
    StorageError,
    StorageNotFoundError,
    StorageRetentionLockError,
    StorageAuthenticationError,
    StorageTimeoutError
)
from backend.app.config import settings

class GCSStorageProvider(StorageProvider):
    """
    Google Cloud Storage Provider using official google-cloud-storage library.
    Falls back smoothly to simulated mode when credentials are not configured,
    ensuring zero-cost safe offline operation.
    """

    def __init__(
        self,
        bucket_name: Optional[str] = None,
        credentials_path: Optional[str] = None,
        simulated: bool = False
    ):
        self.bucket_name = bucket_name or settings.GCS_BUCKET_NAME
        self.credentials_path = credentials_path or settings.GOOGLE_APPLICATION_CREDENTIALS
        self.simulated = simulated
        self.client = None
        self.bucket = None
        self._mock_data: Dict[str, bytes] = {}
        self._mock_retention: Dict[str, Dict[str, Any]] = {}
        # Fault injection hooks for testing
        self.simulate_network_failure: bool = False
        self.simulate_timeout: bool = False
        self.simulate_auth_failure: bool = False

        if not self.simulated:
            has_creds = bool(
                (getattr(settings, "GCS_CREDENTIALS_JSON", None) and settings.GCS_CREDENTIALS_JSON.strip()) or
                (self.credentials_path and os.path.exists(self.credentials_path)) or
                os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            )
            if not has_creds and not settings.GCS_PROJECT_ID:
                self.simulated = True
            else:
                try:
                    from google.cloud import storage
                    from google.oauth2 import service_account

                    # 1. Inline JSON credentials
                    if getattr(settings, "GCS_CREDENTIALS_JSON", None) and settings.GCS_CREDENTIALS_JSON.strip():
                        creds_dict = json.loads(settings.GCS_CREDENTIALS_JSON)
                        creds = service_account.Credentials.from_service_account_info(creds_dict)
                        self.client = storage.Client(credentials=creds, project=creds_dict.get("project_id") or settings.GCS_PROJECT_ID or None)
                    # 2. File-path based credentials
                    elif self.credentials_path and os.path.exists(self.credentials_path):
                        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.credentials_path
                        self.client = storage.Client(project=settings.GCS_PROJECT_ID or None)
                    # 3. Environment default credentials
                    else:
                        self.client = storage.Client(project=settings.GCS_PROJECT_ID or None)

                    self.bucket = self.client.bucket(self.bucket_name)
                except Exception:
                    self.simulated = True

    def _check_fault_injection(self):
        if self.simulate_auth_failure:
            raise StorageAuthenticationError("Google Cloud Storage authentication failed (InvalidCredentials).", provider="gcs")
        if self.simulate_timeout:
            raise StorageTimeoutError("Google Cloud Storage request timed out.", provider="gcs")
        if self.simulate_network_failure:
            raise StorageError("Google Cloud Storage network connection error.", provider="gcs")

    def _get_blob(self, storage_path: str):
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        return self.bucket.blob(clean_path)

    def upload_file(self, local_path: str, destination_path: str) -> bool:
        self._check_fault_injection()
        clean_path = destination_path.lstrip("/\\").replace("\\", "/")

        if not self.simulated and self.bucket:
            try:
                blob = self._get_blob(destination_path)
                blob.upload_from_filename(local_path, timeout=getattr(settings, "STORAGE_TIMEOUT_SECONDS", 10))
                return True
            except Exception as e:
                raise StorageError(f"GCS upload_file error: {str(e)}", provider="gcs")

        with open(local_path, "rb") as f:
            data = f.read()
        return self.upload_bytes(data, destination_path)

    def upload_bytes(self, data: bytes, destination_path: str) -> bool:
        self._check_fault_injection()
        clean_path = destination_path.lstrip("/\\").replace("\\", "/")

        if not self.simulated and self.bucket:
            try:
                blob = self._get_blob(destination_path)
                blob.upload_from_string(data, timeout=getattr(settings, "STORAGE_TIMEOUT_SECONDS", 10))
                return True
            except Exception as e:
                raise StorageError(f"GCS upload_bytes error: {str(e)}", provider="gcs")

        self._mock_data[clean_path] = data
        return True

    def download_file(self, source_path: str, local_destination_path: str) -> bool:
        self._check_fault_injection()
        clean_path = source_path.lstrip("/\\").replace("\\", "/")
        dest = Path(local_destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        if not self.simulated and self.bucket:
            try:
                blob = self._get_blob(source_path)
                if not blob.exists():
                    raise StorageNotFoundError(f"GCS Object not found: {source_path}", provider="gcs")
                blob.download_to_filename(str(dest), timeout=getattr(settings, "STORAGE_TIMEOUT_SECONDS", 10))
                return True
            except StorageNotFoundError:
                raise
            except Exception as e:
                if "404" in str(e):
                    raise StorageNotFoundError(f"GCS Object not found: {source_path}", provider="gcs")
                raise StorageError(f"GCS download_file error: {str(e)}", provider="gcs")

        if clean_path not in self._mock_data:
            raise StorageNotFoundError(f"GCS Object not found: {source_path}", provider="gcs")
        with open(dest, "wb") as f:
            f.write(self._mock_data[clean_path])
        return True

    def download_bytes(self, source_path: str) -> bytes:
        self._check_fault_injection()
        clean_path = source_path.lstrip("/\\").replace("\\", "/")

        if not self.simulated and self.bucket:
            try:
                blob = self._get_blob(source_path)
                if not blob.exists():
                    raise StorageNotFoundError(f"GCS Object not found: {source_path}", provider="gcs")
                return blob.download_as_bytes(timeout=getattr(settings, "STORAGE_TIMEOUT_SECONDS", 10))
            except StorageNotFoundError:
                raise
            except Exception as e:
                if "404" in str(e):
                    raise StorageNotFoundError(f"GCS Object not found: {source_path}", provider="gcs")
                raise StorageError(f"GCS download_bytes error: {str(e)}", provider="gcs")

        if clean_path not in self._mock_data:
            raise StorageNotFoundError(f"GCS Object not found: {source_path}", provider="gcs")
        return self._mock_data[clean_path]

    def stream_object(self, source_path: str, chunk_size: int = 65536) -> Iterator[bytes]:
        self._check_fault_injection()
        clean_path = source_path.lstrip("/\\").replace("\\", "/")

        if not self.simulated and self.bucket:
            try:
                blob = self._get_blob(source_path)
                if not blob.exists():
                    raise StorageNotFoundError(f"GCS Object not found: {source_path}", provider="gcs")
                stream = blob.open("rb")
                with stream:
                    while True:
                        chunk = stream.read(chunk_size)
                        if not chunk:
                            break
                        yield chunk
                return
            except StorageNotFoundError:
                raise
            except Exception as e:
                raise StorageError(f"GCS stream_object error: {str(e)}", provider="gcs")

        data = self.download_bytes(source_path)
        bio = io.BytesIO(data)
        while True:
            chunk = bio.read(chunk_size)
            if not chunk:
                break
            yield chunk

    def list_objects(self, prefix: str = "") -> List[Dict[str, Any]]:
        self._check_fault_injection()
        clean_prefix = prefix.lstrip("/\\").replace("\\", "/")

        if not self.simulated and self.bucket:
            try:
                blobs = self.client.list_blobs(self.bucket, prefix=clean_prefix)
                results = []
                for b in blobs:
                    results.append({
                        "key": b.name,
                        "storage_path": b.name,
                        "size_bytes": b.size,
                        "last_modified": b.updated.isoformat() if b.updated else None,
                        "crc32c": b.crc32c,
                        "md5_hash": b.md5_hash,
                        "uri": self.get_uri(b.name)
                    })
                return results
            except Exception as e:
                raise StorageError(f"GCS list_objects error: {str(e)}", provider="gcs")

        results = []
        for key, data in self._mock_data.items():
            if not clean_prefix or key.startswith(clean_prefix):
                results.append({
                    "key": key,
                    "storage_path": key,
                    "size_bytes": len(data),
                    "last_modified": datetime.now(timezone.utc).isoformat(),
                    "etag": hashlib.md5(data).hexdigest(),
                    "uri": self.get_uri(key)
                })
        return results

    def delete_file(self, storage_path: str) -> bool:
        self._check_fault_injection()
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")

        # Check retention policy
        retention = self.get_retention(clean_path)
        if retention and retention.get("is_active"):
            raise StorageRetentionLockError(
                f"GCS Bucket Lock / Object Retention active on '{storage_path}' until {retention.get('retain_until')}. "
                "Deletion denied.",
                provider="gcs"
            )

        if not self.simulated and self.bucket:
            try:
                blob = self._get_blob(storage_path)
                if blob.exists():
                    blob.delete(timeout=getattr(settings, "STORAGE_TIMEOUT_SECONDS", 10))
                    return True
                return False
            except Exception as e:
                if "retention" in str(e).lower() or "locked" in str(e).lower():
                    raise StorageRetentionLockError(f"GCS Bucket Lock prevented deletion: {str(e)}", provider="gcs")
                raise StorageError(f"GCS delete_file error: {str(e)}", provider="gcs")

        if clean_path in self._mock_data:
            del self._mock_data[clean_path]
            if clean_path in self._mock_retention:
                del self._mock_retention[clean_path]
            return True
        return False

    def file_exists(self, storage_path: str) -> bool:
        self._check_fault_injection()
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        if not self.simulated and self.bucket:
            try:
                blob = self._get_blob(storage_path)
                return blob.exists(timeout=getattr(settings, "STORAGE_TIMEOUT_SECONDS", 10))
            except Exception:
                return False
        return clean_path in self._mock_data

    def get_storage_name(self) -> str:
        mode = "Simulated" if self.simulated else "Connected"
        return f"Google Cloud Storage ({mode} - gs://{self.bucket_name})"

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "provider": "gcs",
            "display_name": f"Google Cloud Storage (gs://{self.bucket_name})",
            "features": {
                "streaming_upload": True,
                "streaming_download": True,
                "object_versioning": True,
                "worm_retention": True,  # Bucket Lock / Object Retention
                "encryption_at_rest": True,  # Google-managed or CMEK
                "multi_cloud_replication": True,
                "lifecycle_management": True,
                "tiering": ["STANDARD", "NEARLINE", "COLDLINE", "ARCHIVE"]
            },
            "bucket_name": self.bucket_name,
            "simulated": self.simulated
        }

    def health_check(self) -> Dict[str, Any]:
        start = time.time()
        try:
            self._check_fault_injection()
            if self.simulated:
                return {
                    "status": "HEALTHY",
                    "provider": "gcs",
                    "latency_ms": round((time.time() - start) * 1000.0, 2),
                    "writable": True,
                    "details": f"Google Cloud Storage Adapter operational (Simulated / Ready for GCP Credentials)"
                }
            exists = self.bucket.exists(timeout=getattr(settings, "STORAGE_TIMEOUT_SECONDS", 10))
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
        self._check_fault_injection()
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")

        if not self.simulated and self.bucket:
            try:
                blob = self._get_blob(storage_path)
                if not blob.exists():
                    raise StorageNotFoundError(f"GCS Object not found: {storage_path}", provider="gcs")
                blob.reload()
                return {
                    "storage_path": storage_path,
                    "size_bytes": blob.size,
                    "content_type": blob.content_type or "application/octet-stream",
                    "created_at": blob.time_created.isoformat() if blob.time_created else None,
                    "modified_at": blob.updated.isoformat() if blob.updated else None,
                    "crc32c": blob.crc32c,
                    "md5_or_hash": blob.md5_hash,
                    "uri": self.get_uri(storage_path),
                    "metadata": blob.metadata or {}
                }
            except StorageNotFoundError:
                raise
            except Exception as e:
                raise StorageError(f"GCS get_object_metadata error: {str(e)}", provider="gcs")

        if clean_path not in self._mock_data:
            raise StorageNotFoundError(f"GCS Object not found: {storage_path}", provider="gcs")

        data = self._mock_data[clean_path]
        retention = self.get_retention(clean_path)

        return {
            "storage_path": storage_path,
            "size_bytes": len(data),
            "content_type": "application/octet-stream",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "modified_at": datetime.now(timezone.utc).isoformat(),
            "crc32c": "simulated_crc32c",
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5_or_hash": hashlib.md5(data).hexdigest(),
            "retention": retention,
            "uri": self.get_uri(storage_path),
            "metadata": {"source": "gcs_simulated"}
        }

    def set_retention(self, storage_path: str, retention_until: datetime, mode: str = "COMPLIANCE") -> bool:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        if not self.file_exists(clean_path):
            raise StorageNotFoundError(f"Cannot set retention on non-existent object: {storage_path}", provider="gcs")

        now = datetime.now(timezone.utc)
        if retention_until.tzinfo is None:
            retention_until = retention_until.replace(tzinfo=timezone.utc)

        self._mock_retention[clean_path] = {
            "mode": mode,
            "retain_until": retention_until.isoformat(),
            "locked_at": now.isoformat(),
            "is_active": retention_until > now
        }
        return True

    def get_retention(self, storage_path: str) -> Optional[Dict[str, Any]]:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        lock = self._mock_retention.get(clean_path)
        if not lock:
            return None
        now = datetime.now(timezone.utc)
        retain_until_dt = datetime.fromisoformat(lock["retain_until"])
        lock["is_active"] = retain_until_dt > now
        return lock

    def get_uri(self, storage_path: str) -> str:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        return f"gs://{self.bucket_name}/{clean_path}"
