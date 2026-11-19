import os
import io
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from backend.app.storage.base import StorageProvider
from backend.app.config import settings

class S3StorageProvider(StorageProvider):
    """
    AWS S3 Multi-Cloud Storage Adapter.
    Uses boto3 client when credentials are provided; falls back gracefully
    to sandbox simulation when AWS credentials are not configured.
    """

    def __init__(
        self,
        bucket_name: Optional[str] = None,
        region_name: Optional[str] = None,
        simulated: bool = False
    ):
        self.bucket_name = bucket_name or getattr(settings, "AWS_S3_BUCKET", "cloudvault-s3-backup")
        self.region_name = region_name or getattr(settings, "AWS_REGION", "us-east-1")
        self.simulated = simulated
        self.client = None
        self._mock_data = {}

        if not self.simulated:
            try:
                import boto3
                from botocore.config import Config
                self.client = boto3.client(
                    "s3",
                    region_name=self.region_name,
                    config=Config(connect_timeout=3, read_timeout=3, retries={"max_attempts": 2})
                )
            except Exception:
                # Fallback to simulated mode
                self.simulated = True

    def upload_file(self, local_path: str, destination_path: str) -> bool:
        clean_path = destination_path.lstrip("/\\").replace("\\", "/")
        if not self.simulated and self.client:
            self.client.upload_file(local_path, self.bucket_name, clean_path)
            return True
        with open(local_path, "rb") as f:
            self._mock_data[clean_path] = f.read()
        return True

    def upload_bytes(self, data: bytes, destination_path: str) -> bool:
        clean_path = destination_path.lstrip("/\\").replace("\\", "/")
        if not self.simulated and self.client:
            self.client.put_object(Bucket=self.bucket_name, Key=clean_path, Body=data)
            return True
        self._mock_data[clean_path] = data
        return True

    def download_file(self, source_path: str, local_destination_path: str) -> bool:
        clean_path = source_path.lstrip("/\\").replace("\\", "/")
        dest = Path(local_destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not self.simulated and self.client:
            self.client.download_file(self.bucket_name, clean_path, str(dest))
            return True
        if clean_path not in self._mock_data:
            raise FileNotFoundError(f"S3 Object not found: {source_path}")
        with open(dest, "wb") as f:
            f.write(self._mock_data[clean_path])
        return True

    def download_bytes(self, source_path: str) -> bytes:
        clean_path = source_path.lstrip("/\\").replace("\\", "/")
        if not self.simulated and self.client:
            resp = self.client.get_object(Bucket=self.bucket_name, Key=clean_path)
            return resp["Body"].read()
        if clean_path not in self._mock_data:
            raise FileNotFoundError(f"S3 Object not found: {source_path}")
        return self._mock_data[clean_path]

    def delete_file(self, storage_path: str) -> bool:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        if not self.simulated and self.client:
            self.client.delete_object(Bucket=self.bucket_name, Key=clean_path)
            return True
        if clean_path in self._mock_data:
            del self._mock_data[clean_path]
            return True
        return False

    def file_exists(self, storage_path: str) -> bool:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        if not self.simulated and self.client:
            try:
                self.client.head_object(Bucket=self.bucket_name, Key=clean_path)
                return True
            except Exception:
                return False
        return clean_path in self._mock_data

    def get_storage_name(self) -> str:
        mode = "Simulated" if self.simulated else "Connected"
        return f"Amazon S3 ({mode} - s3://{self.bucket_name})"

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "provider": "s3",
            "display_name": f"Amazon Simple Storage Service (S3)",
            "features": {
                "streaming_upload": True,
                "object_versioning": True,
                "worm_retention": True,  # S3 Object Lock
                "encryption_at_rest": True,  # SSE-S3 / SSE-KMS
                "multi_cloud_replication": True,
                "lifecycle_management": True,
                "tiering": ["STANDARD", "INTELLIGENT_TIERING", "GLACIER", "DEEP_ARCHIVE"]
            },
            "bucket_name": self.bucket_name,
            "region": self.region_name,
            "simulated": self.simulated
        }

    def health_check(self) -> Dict[str, Any]:
        start = time.time()
        if self.simulated:
            return {
                "status": "HEALTHY",
                "provider": "s3",
                "latency_ms": round((time.time() - start) * 1000.0, 2),
                "writable": True,
                "details": f"AWS S3 Adapter operational (Simulated / Ready for AWS Credentials)"
            }
        try:
            self.client.head_bucket(Bucket=self.bucket_name)
            latency_ms = round((time.time() - start) * 1000.0, 2)
            return {
                "status": "HEALTHY",
                "provider": "s3",
                "latency_ms": latency_ms,
                "writable": True,
                "details": f"Connected to AWS S3 bucket {self.bucket_name} in {self.region_name}"
            }
        except Exception as e:
            return {
                "status": "UNAVAILABLE",
                "provider": "s3",
                "latency_ms": -1,
                "writable": False,
                "details": f"AWS S3 connection failed: {str(e)}"
            }

    def get_object_metadata(self, storage_path: str) -> Dict[str, Any]:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        if not self.simulated and self.client:
            resp = self.client.head_object(Bucket=self.bucket_name, Key=clean_path)
            return {
                "storage_path": storage_path,
                "size_bytes": resp["ContentLength"],
                "content_type": resp.get("ContentType", "application/octet-stream"),
                "created_at": resp.get("LastModified", datetime.utcnow()).isoformat(),
                "modified_at": resp.get("LastModified", datetime.utcnow()).isoformat(),
                "etag": resp.get("ETag", "").strip('"'),
                "metadata": resp.get("Metadata", {})
            }
        if clean_path not in self._mock_data:
            raise FileNotFoundError(f"S3 Object not found: {storage_path}")
        data = self._mock_data[clean_path]
        return {
            "storage_path": storage_path,
            "size_bytes": len(data),
            "content_type": "application/octet-stream",
            "created_at": datetime.utcnow().isoformat(),
            "modified_at": datetime.utcnow().isoformat(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "metadata": {"adapter": "s3_simulated"}
        }

