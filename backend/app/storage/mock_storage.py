import os
import io
import shutil
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Iterator

from backend.app.storage.base import StorageProvider
from backend.app.storage.exceptions import (
    StorageError,
    StorageNotFoundError,
    StorageRetentionLockError,
    StorageTimeoutError,
    StorageAuthenticationError
)
from backend.app.config import settings

class MockStorageProvider(StorageProvider):
    """Local mock storage provider emulating cloud bucket on local disk."""

    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir or settings.MOCK_STORAGE_DIR).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._retention_locks: Dict[str, Dict[str, Any]] = {}
        # Fault injection hooks for testing retry/failover/timeouts
        self.simulate_network_failure: bool = False
        self.simulate_timeout: bool = False
        self.simulate_auth_failure: bool = False

    def _resolve_path(self, storage_path: str) -> Path:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        target = self.base_dir / clean_path
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def _check_fault_injection(self):
        if self.simulate_auth_failure:
            raise StorageAuthenticationError("Simulated mock storage authentication failure.", provider="mock")
        if self.simulate_timeout:
            raise StorageTimeoutError("Simulated mock storage network timeout.", provider="mock")
        if self.simulate_network_failure:
            raise StorageError("Simulated mock storage I/O connection failure.", provider="mock")

    def upload_file(self, local_path: str, destination_path: str) -> bool:
        self._check_fault_injection()
        target = self._resolve_path(destination_path)
        shutil.copy2(local_path, target)
        return True

    def upload_bytes(self, data: bytes, destination_path: str) -> bool:
        self._check_fault_injection()
        target = self._resolve_path(destination_path)
        with open(target, "wb") as f:
            f.write(data)
        return True

    def download_file(self, source_path: str, local_destination_path: str) -> bool:
        self._check_fault_injection()
        target = self._resolve_path(source_path)
        if not target.exists():
            raise StorageNotFoundError(f"Storage object not found: {source_path}", provider="mock")
        dest = Path(local_destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, dest)
        return True

    def download_bytes(self, source_path: str) -> bytes:
        self._check_fault_injection()
        target = self._resolve_path(source_path)
        if not target.exists():
            raise StorageNotFoundError(f"Storage object not found: {source_path}", provider="mock")
        with open(target, "rb") as f:
            return f.read()

    def stream_object(self, source_path: str, chunk_size: int = 65536) -> Iterator[bytes]:
        self._check_fault_injection()
        target = self._resolve_path(source_path)
        if not target.exists():
            raise StorageNotFoundError(f"Storage object not found: {source_path}", provider="mock")
        with open(target, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    def list_objects(self, prefix: str = "") -> List[Dict[str, Any]]:
        self._check_fault_injection()
        clean_prefix = prefix.lstrip("/\\").replace("\\", "/")
        results = []
        if not self.base_dir.exists():
            return results

        for path in self.base_dir.rglob("*"):
            if path.is_file() and not path.name.startswith("."):
                rel_path = path.relative_to(self.base_dir).as_posix()
                if not clean_prefix or rel_path.startswith(clean_prefix):
                    stat = path.stat()
                    results.append({
                        "key": rel_path,
                        "storage_path": rel_path,
                        "size_bytes": stat.st_size,
                        "last_modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                        "uri": self.get_uri(rel_path)
                    })
        return results

    def delete_file(self, storage_path: str) -> bool:
        self._check_fault_injection()
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        retention = self.get_retention(clean_path)
        if retention and retention.get("is_active"):
            raise StorageRetentionLockError(
                f"Object '{storage_path}' is protected under WORM retention until {retention.get('retain_until')}. "
                "Deletion rejected.",
                provider="mock"
            )

        target = self._resolve_path(clean_path)
        if target.exists():
            target.unlink()
            if clean_path in self._retention_locks:
                del self._retention_locks[clean_path]
            return True
        return False

    def file_exists(self, storage_path: str) -> bool:
        self._check_fault_injection()
        target = self._resolve_path(storage_path)
        return target.exists() and target.is_file()

    def get_storage_name(self) -> str:
        return "Local Mock Cloud Storage"

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "provider": "mock",
            "display_name": "Local Mock Cloud Storage Provider",
            "features": {
                "streaming_upload": True,
                "streaming_download": True,
                "object_versioning": False,
                "worm_retention": True,
                "encryption_at_rest": True,
                "multi_cloud_replication": False,
                "lifecycle_management": False,
                "tiering": ["STANDARD", "COLD_SIMULATED"]
            },
            "root_path": str(self.base_dir),
            "simulated": True
        }

    def health_check(self) -> Dict[str, Any]:
        start = time.time()
        test_file = self.base_dir / ".health_probe.tmp"
        try:
            self._check_fault_injection()
            test_file.write_text("health_check_ok")
            content = test_file.read_text()
            test_file.unlink()
            latency_ms = round((time.time() - start) * 1000.0, 2)
            return {
                "status": "HEALTHY",
                "provider": "mock",
                "latency_ms": latency_ms,
                "writable": True,
                "details": f"Local filesystem responsive ({self.base_dir})"
            }
        except Exception as e:
            return {
                "status": "UNAVAILABLE",
                "provider": "mock",
                "latency_ms": -1,
                "writable": False,
                "details": f"Mock storage write failure: {str(e)}"
            }

    def get_object_metadata(self, storage_path: str) -> Dict[str, Any]:
        self._check_fault_injection()
        target = self._resolve_path(storage_path)
        if not target.exists():
            raise StorageNotFoundError(f"Object not found: {storage_path}", provider="mock")

        stat = target.stat()
        with open(target, "rb") as f:
            data = f.read()
            digest = hashlib.sha256(data).hexdigest()

        retention = self.get_retention(storage_path)

        return {
            "storage_path": storage_path,
            "size_bytes": stat.st_size,
            "content_type": "application/octet-stream",
            "created_at": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
            "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "sha256": digest,
            "retention": retention,
            "uri": self.get_uri(storage_path),
            "metadata": {"source": "local_mock"}
        }

    def set_retention(self, storage_path: str, retention_until: datetime, mode: str = "COMPLIANCE") -> bool:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        if not self.file_exists(clean_path):
            raise StorageNotFoundError(f"Cannot set retention on non-existent object: {storage_path}", provider="mock")

        now = datetime.now(timezone.utc)
        if retention_until.tzinfo is None:
            retention_until = retention_until.replace(tzinfo=timezone.utc)

        self._retention_locks[clean_path] = {
            "mode": mode,
            "retain_until": retention_until.isoformat(),
            "locked_at": now.isoformat(),
            "is_active": retention_until > now
        }
        return True

    def get_retention(self, storage_path: str) -> Optional[Dict[str, Any]]:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        lock = self._retention_locks.get(clean_path)
        if not lock:
            return None
        now = datetime.now(timezone.utc)
        retain_until_dt = datetime.fromisoformat(lock["retain_until"])
        lock["is_active"] = retain_until_dt > now
        return lock

    def get_uri(self, storage_path: str) -> str:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        return f"mock://objects/{clean_path}"
