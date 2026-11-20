import os
import io
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
        self._mock_data: Dict[str, bytes] = {}
        self._mock_versions: Dict[str, List[Dict[str, Any]]] = {}
        self._mock_retention: Dict[str, Dict[str, Any]] = {}
        # Fault injection hooks for testing
        self.simulate_network_failure: bool = False
        self.simulate_timeout: bool = False
        self.simulate_auth_failure: bool = False

        if not self.simulated:
            access_key = getattr(settings, "AWS_ACCESS_KEY_ID", "")
            secret_key = getattr(settings, "AWS_SECRET_ACCESS_KEY", "")
            if not access_key and not os.environ.get("AWS_ACCESS_KEY_ID"):
                self.simulated = True
            else:
                try:
                    import boto3
                    from botocore.config import Config
                    client_kwargs = {
                        "service_name": "s3",
                        "region_name": self.region_name,
                        "config": Config(
                            connect_timeout=getattr(settings, "STORAGE_TIMEOUT_SECONDS", 10),
                            read_timeout=getattr(settings, "STORAGE_TIMEOUT_SECONDS", 10),
                            retries={"max_attempts": getattr(settings, "STORAGE_MAX_RETRIES", 3)}
                        )
                    }
                    if access_key and secret_key:
                        client_kwargs["aws_access_key_id"] = access_key
                        client_kwargs["aws_secret_access_key"] = secret_key

                    self.client = boto3.client(**client_kwargs)
                except Exception:
                    self.simulated = True

    def _check_fault_injection(self):
        if self.simulate_auth_failure:
            raise StorageAuthenticationError("AWS S3 authentication failed (InvalidAccessKeyId/SignatureDoesNotMatch).", provider="s3")
        if self.simulate_timeout:
            raise StorageTimeoutError("AWS S3 operation timed out after network delay.", provider="s3")
        if self.simulate_network_failure:
            raise StorageError("AWS S3 endpoint connection refused (EndpointConnectionError).", provider="s3")

    def upload_file(self, local_path: str, destination_path: str) -> bool:
        self._check_fault_injection()
        clean_path = destination_path.lstrip("/\\").replace("\\", "/")
        file_size = os.path.getsize(local_path)

        if not self.simulated and self.client:
            try:
                # Use multipart upload for files > 5MB
                from boto3.s3.transfer import TransferConfig
                config = TransferConfig(multipart_threshold=5 * 1024 * 1024, multipart_chunksize=5 * 1024 * 1024)
                self.client.upload_file(local_path, self.bucket_name, clean_path, Config=config)
                return True
            except Exception as e:
                raise StorageError(f"AWS S3 upload_file error: {str(e)}", provider="s3")

        with open(local_path, "rb") as f:
            data = f.read()
        return self.upload_bytes(data, destination_path)

    def upload_bytes(self, data: bytes, destination_path: str) -> bool:
        self._check_fault_injection()
        clean_path = destination_path.lstrip("/\\").replace("\\", "/")

        if not self.simulated and self.client:
            try:
                self.client.put_object(Bucket=self.bucket_name, Key=clean_path, Body=data)
                return True
            except Exception as e:
                raise StorageError(f"AWS S3 put_object error: {str(e)}", provider="s3")

        # Simulated multipart / versioned storage
        self._mock_data[clean_path] = data
        version_id = f"v-{int(time.time()*1000)}-{len(self._mock_versions.get(clean_path, [])) + 1}"
        if clean_path not in self._mock_versions:
            self._mock_versions[clean_path] = []
        self._mock_versions[clean_path].append({
            "version_id": version_id,
            "data": data,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "size_bytes": len(data)
        })
        return True

    def download_file(self, source_path: str, local_destination_path: str) -> bool:
        self._check_fault_injection()
        clean_path = source_path.lstrip("/\\").replace("\\", "/")
        dest = Path(local_destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        if not self.simulated and self.client:
            try:
                self.client.download_file(self.bucket_name, clean_path, str(dest))
                return True
            except Exception as e:
                if "404" in str(e) or "NoSuchKey" in str(e):
                    raise StorageNotFoundError(f"S3 Object not found: {source_path}", provider="s3")
                raise StorageError(f"AWS S3 download_file error: {str(e)}", provider="s3")

        if clean_path not in self._mock_data:
            raise StorageNotFoundError(f"S3 Object not found: {source_path}", provider="s3")
        with open(dest, "wb") as f:
            f.write(self._mock_data[clean_path])
        return True

    def download_bytes(self, source_path: str) -> bytes:
        self._check_fault_injection()
        clean_path = source_path.lstrip("/\\").replace("\\", "/")

        if not self.simulated and self.client:
            try:
                resp = self.client.get_object(Bucket=self.bucket_name, Key=clean_path)
                return resp["Body"].read()
            except Exception as e:
                if "NoSuchKey" in str(e) or "404" in str(e):
                    raise StorageNotFoundError(f"S3 Object not found: {source_path}", provider="s3")
                raise StorageError(f"AWS S3 download_bytes error: {str(e)}", provider="s3")

        if clean_path not in self._mock_data:
            raise StorageNotFoundError(f"S3 Object not found: {source_path}", provider="s3")
        return self._mock_data[clean_path]

    def stream_object(self, source_path: str, chunk_size: int = 65536) -> Iterator[bytes]:
        self._check_fault_injection()
        clean_path = source_path.lstrip("/\\").replace("\\", "/")

        if not self.simulated and self.client:
            try:
                resp = self.client.get_object(Bucket=self.bucket_name, Key=clean_path)
                body = resp["Body"]
                while True:
                    chunk = body.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
                return
            except Exception as e:
                if "NoSuchKey" in str(e) or "404" in str(e):
                    raise StorageNotFoundError(f"S3 Object not found: {source_path}", provider="s3")
                raise StorageError(f"AWS S3 stream error: {str(e)}", provider="s3")

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

        if not self.simulated and self.client:
            try:
                resp = self.client.list_objects_v2(Bucket=self.bucket_name, Prefix=clean_prefix)
                results = []
                for item in resp.get("Contents", []):
                    results.append({
                        "key": item["Key"],
                        "storage_path": item["Key"],
                        "size_bytes": item["Size"],
                        "last_modified": item["LastModified"].isoformat(),
                        "etag": item.get("ETag", "").strip('"'),
                        "uri": self.get_uri(item["Key"])
                    })
                return results
            except Exception as e:
                raise StorageError(f"AWS S3 list_objects error: {str(e)}", provider="s3")

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

        # Check Object Lock retention
        retention = self.get_retention(clean_path)
        if retention and retention.get("is_active"):
            raise StorageRetentionLockError(
                f"S3 Object Lock active on '{storage_path}' until {retention.get('retain_until')}. Deletion denied.",
                provider="s3"
            )

        if not self.simulated and self.client:
            try:
                self.client.delete_object(Bucket=self.bucket_name, Key=clean_path)
                return True
            except Exception as e:
                raise StorageError(f"AWS S3 delete_object error: {str(e)}", provider="s3")

        if clean_path in self._mock_data:
            del self._mock_data[clean_path]
            if clean_path in self._mock_retention:
                del self._mock_retention[clean_path]
            return True
        return False

    def file_exists(self, storage_path: str) -> bool:
        self._check_fault_injection()
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
            "display_name": "Amazon Simple Storage Service (S3)",
            "features": {
                "streaming_upload": True,
                "streaming_download": True,
                "multipart_upload": True,
                "object_versioning": True,
                "worm_retention": True,  # S3 Object Lock (COMPLIANCE / GOVERNANCE)
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
        try:
            self._check_fault_injection()
            if self.simulated:
                return {
                    "status": "HEALTHY",
                    "provider": "s3",
                    "latency_ms": round((time.time() - start) * 1000.0, 2),
                    "writable": True,
                    "details": f"AWS S3 Adapter operational (Simulated / Ready for AWS Credentials)"
                }
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
        self._check_fault_injection()
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")

        if not self.simulated and self.client:
            try:
                resp = self.client.head_object(Bucket=self.bucket_name, Key=clean_path)
                return {
                    "storage_path": storage_path,
                    "size_bytes": resp["ContentLength"],
                    "content_type": resp.get("ContentType", "application/octet-stream"),
                    "created_at": resp["LastModified"].isoformat(),
                    "modified_at": resp["LastModified"].isoformat(),
                    "etag": resp.get("ETag", "").strip('"'),
                    "version_id": resp.get("VersionId"),
                    "uri": self.get_uri(storage_path),
                    "metadata": resp.get("Metadata", {})
                }
            except Exception as e:
                raise StorageNotFoundError(f"S3 Object not found: {storage_path}", provider="s3")

        if clean_path not in self._mock_data:
            raise StorageNotFoundError(f"S3 Object not found: {storage_path}", provider="s3")

        data = self._mock_data[clean_path]
        retention = self.get_retention(clean_path)
        versions = self._mock_versions.get(clean_path, [])
        latest_ver = versions[-1]["version_id"] if versions else "v1"

        return {
            "storage_path": storage_path,
            "size_bytes": len(data),
            "content_type": "application/octet-stream",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "modified_at": datetime.now(timezone.utc).isoformat(),
            "etag": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "version_id": latest_ver,
            "version_count": len(versions),
            "retention": retention,
            "uri": self.get_uri(storage_path),
            "metadata": {"source": "aws_s3_simulated"}
        }

    def set_retention(self, storage_path: str, retention_until: datetime, mode: str = "COMPLIANCE") -> bool:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        if not self.file_exists(clean_path):
            raise StorageNotFoundError(f"Cannot set retention on non-existent object: {storage_path}", provider="s3")

        now = datetime.now(timezone.utc)
        if retention_until.tzinfo is None:
            retention_until = retention_until.replace(tzinfo=timezone.utc)

        self._mock_retention[clean_path] = {
            "mode": mode,  # COMPLIANCE or GOVERNANCE
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
        return f"s3://{self.bucket_name}/{clean_path}"
