import os
import shutil
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
from backend.app.storage.base import StorageProvider
from backend.app.config import settings

class MockStorageProvider(StorageProvider):
    """Local mock storage provider emulating cloud bucket on local disk."""

    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir or settings.MOCK_STORAGE_DIR).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_path(self, storage_path: str) -> Path:
        # Sanitize path to prevent directory traversal
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        target = self.base_dir / clean_path
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def upload_file(self, local_path: str, destination_path: str) -> bool:
        target = self._resolve_path(destination_path)
        shutil.copy2(local_path, target)
        return True

    def upload_bytes(self, data: bytes, destination_path: str) -> bool:
        target = self._resolve_path(destination_path)
        with open(target, "wb") as f:
            f.write(data)
        return True

    def download_file(self, source_path: str, local_destination_path: str) -> bool:
        target = self._resolve_path(source_path)
        if not target.exists():
            raise FileNotFoundError(f"Storage object not found: {source_path}")
        dest = Path(local_destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, dest)
        return True

    def download_bytes(self, source_path: str) -> bytes:
        target = self._resolve_path(source_path)
        if not target.exists():
            raise FileNotFoundError(f"Storage object not found: {source_path}")
        with open(target, "rb") as f:
            return f.read()

    def delete_file(self, storage_path: str) -> bool:
        target = self._resolve_path(storage_path)
        if target.exists():
            target.unlink()
            return True
        return False

    def file_exists(self, storage_path: str) -> bool:
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
        target = self._resolve_path(storage_path)
        if not target.exists():
            raise FileNotFoundError(f"Object not found: {storage_path}")

        stat = target.stat()
        with open(target, "rb") as f:
            data = f.read()
            digest = hashlib.sha256(data).hexdigest()

        return {
            "storage_path": storage_path,
            "size_bytes": stat.st_size,
            "content_type": "application/octet-stream",
            "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "sha256": digest,
            "metadata": {"source": "local_mock"}
        }
