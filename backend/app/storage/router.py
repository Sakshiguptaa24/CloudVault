import io
import time
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Iterator, Tuple
from sqlalchemy.orm import Session

from backend.app.storage.base import StorageProvider
from backend.app.storage.exceptions import (
    StorageError,
    StorageNotFoundError,
    StorageRetentionLockError,
    StorageAuthenticationError,
    StorageTimeoutError,
    StorageIntegrityError
)
from backend.app.config import settings

logger = logging.getLogger("cloudvault.storage.router")

class MultiCloudRouter(StorageProvider):
    """
    Intelligent Multi-Cloud Storage Router with Automatic Failover,
    Exponential Backoff Retries, Health Telemetry, and Cross-Provider Migration.
    """

    def __init__(
        self,
        primary_provider: Optional[StorageProvider] = None,
        secondary_provider: Optional[StorageProvider] = None,
        max_retries: int = None,
        retry_backoff: float = None,
        failover_enabled: bool = None
    ):
        self.primary = primary_provider
        self.secondary = secondary_provider
        self.max_retries = max_retries if max_retries is not None else getattr(settings, "STORAGE_MAX_RETRIES", 3)
        self.retry_backoff = retry_backoff if retry_backoff is not None else getattr(settings, "STORAGE_RETRY_BACKOFF", 0.5)
        self.failover_enabled = failover_enabled if failover_enabled is not None else getattr(settings, "STORAGE_FAILOVER_ENABLED", True)

        # Operational Telemetry
        self.telemetry = {
            "uploads_count": 0,
            "downloads_count": 0,
            "bytes_uploaded": 0,
            "bytes_downloaded": 0,
            "retries_count": 0,
            "failover_events_count": 0,
            "failover_log": []
        }

    def _execute_with_retry(self, action_name: str, func, *args, **kwargs) -> Any:
        """Execute a storage callable with exponential backoff on transient errors."""
        last_err = None
        for attempt in range(1, self.max_retries + 1):
            try:
                return func(*args, **kwargs)
            except (StorageTimeoutError, StorageAuthenticationError) as e:
                # Immediate failover triggers
                raise e
            except Exception as e:
                last_err = e
                self.telemetry["retries_count"] += 1
                logger.warning(
                    f"Storage operation '{action_name}' attempt {attempt}/{self.max_retries} failed ({e})."
                )
                if attempt < self.max_retries:
                    time.sleep(self.retry_backoff * (2 ** (attempt - 1)))
        raise last_err

    def upload_bytes(self, data: bytes, destination_path: str) -> bool:
        """
        Upload bytes with primary provider retry and automatic secondary failover.
        Ensures atomic upload without silent file loss.
        """
        clean_path = destination_path.lstrip("/\\").replace("\\", "/")
        try:
            res = self._execute_with_retry("upload_bytes_primary", self.primary.upload_bytes, data, destination_path)
            self.telemetry["uploads_count"] += 1
            self.telemetry["bytes_uploaded"] += len(data)
            return res
        except Exception as primary_err:
            if not self.failover_enabled or not self.secondary:
                raise primary_err

            # Trigger explicit failover
            failover_record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "destination_path": clean_path,
                "primary_provider": self.primary.get_storage_name(),
                "secondary_provider": self.secondary.get_storage_name(),
                "error_reason": str(primary_err),
                "status": "FAILOVER_INITIATED"
            }
            logger.warning(
                f"🚨 Primary storage provider '{self.primary.get_storage_name()}' failed for '{clean_path}' ({primary_err}). "
                f"Failing over to secondary '{self.secondary.get_storage_name()}'."
            )

            try:
                res = self._execute_with_retry("upload_bytes_secondary", self.secondary.upload_bytes, data, destination_path)
                failover_record["status"] = "FAILOVER_COMPLETED"
                self.telemetry["failover_events_count"] += 1
                self.telemetry["failover_log"].append(failover_record)
                self.telemetry["uploads_count"] += 1
                self.telemetry["bytes_uploaded"] += len(data)
                return res
            except Exception as sec_err:
                failover_record["status"] = f"FAILOVER_FAILED: {str(sec_err)}"
                self.telemetry["failover_log"].append(failover_record)
                raise StorageError(
                    f"Both primary ({primary_err}) and secondary ({sec_err}) storage uploads failed for '{clean_path}'."
                )

    def upload_file(self, local_path: str, destination_path: str) -> bool:
        """Upload file with primary retry and secondary failover."""
        clean_path = destination_path.lstrip("/\\").replace("\\", "/")
        try:
            res = self._execute_with_retry("upload_file_primary", self.primary.upload_file, local_path, destination_path)
            self.telemetry["uploads_count"] += 1
            return res
        except Exception as primary_err:
            if not self.failover_enabled or not self.secondary:
                raise primary_err

            failover_record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "destination_path": clean_path,
                "primary_provider": self.primary.get_storage_name(),
                "secondary_provider": self.secondary.get_storage_name(),
                "error_reason": str(primary_err),
                "status": "FAILOVER_INITIATED"
            }
            try:
                res = self._execute_with_retry("upload_file_secondary", self.secondary.upload_file, local_path, destination_path)
                failover_record["status"] = "FAILOVER_COMPLETED"
                self.telemetry["failover_events_count"] += 1
                self.telemetry["failover_log"].append(failover_record)
                self.telemetry["uploads_count"] += 1
                return res
            except Exception as sec_err:
                failover_record["status"] = f"FAILOVER_FAILED: {str(sec_err)}"
                self.telemetry["failover_log"].append(failover_record)
                raise StorageError(f"Both primary and secondary uploads failed for file '{local_path}'.")

    def download_bytes(self, source_path: str, preferred_provider: Optional[StorageProvider] = None) -> bytes:
        """Download bytes from preferred provider, primary, or secondary failover."""
        clean_path = source_path.lstrip("/\\").replace("\\", "/")
        providers_to_try = []
        if preferred_provider:
            providers_to_try.append(preferred_provider)
        if self.primary and self.primary not in providers_to_try:
            providers_to_try.append(self.primary)
        if self.secondary and self.secondary not in providers_to_try:
            providers_to_try.append(self.secondary)

        last_err = None
        for p in providers_to_try:
            try:
                if p.file_exists(clean_path):
                    data = p.download_bytes(clean_path)
                    self.telemetry["downloads_count"] += 1
                    self.telemetry["bytes_downloaded"] += len(data)
                    return data
            except Exception as e:
                last_err = e

        raise StorageNotFoundError(f"Storage object '{source_path}' not found on any active provider. ({last_err})")

    def download_file(self, source_path: str, local_destination_path: str, preferred_provider: Optional[StorageProvider] = None) -> bool:
        """Download file from preferred provider, primary, or secondary failover."""
        clean_path = source_path.lstrip("/\\").replace("\\", "/")
        providers_to_try = []
        if preferred_provider:
            providers_to_try.append(preferred_provider)
        if self.primary and self.primary not in providers_to_try:
            providers_to_try.append(self.primary)
        if self.secondary and self.secondary not in providers_to_try:
            providers_to_try.append(self.secondary)

        for p in providers_to_try:
            try:
                if p.file_exists(clean_path):
                    res = p.download_file(clean_path, local_destination_path)
                    self.telemetry["downloads_count"] += 1
                    return res
            except Exception:
                continue

        raise StorageNotFoundError(f"Storage object '{source_path}' not found for download on any active provider.")

    def stream_object(self, source_path: str, chunk_size: int = 65536) -> Iterator[bytes]:
        """Stream object bytes from available provider."""
        clean_path = source_path.lstrip("/\\").replace("\\", "/")
        if self.primary and self.primary.file_exists(clean_path):
            yield from self.primary.stream_object(clean_path, chunk_size)
            return
        if self.secondary and self.secondary.file_exists(clean_path):
            yield from self.secondary.stream_object(clean_path, chunk_size)
            return
        raise StorageNotFoundError(f"Storage object '{source_path}' not found for streaming.")

    def delete_file(self, storage_path: str) -> bool:
        """Delete object across providers, respecting retention locks."""
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        deleted = False

        # Attempt primary
        if self.primary and self.primary.file_exists(clean_path):
            deleted = self.primary.delete_file(clean_path) or deleted

        # Attempt secondary
        if self.secondary and self.secondary.file_exists(clean_path):
            deleted = self.secondary.delete_file(clean_path) or deleted

        return deleted

    def file_exists(self, storage_path: str) -> bool:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        if self.primary and self.primary.file_exists(clean_path):
            return True
        if self.secondary and self.secondary.file_exists(clean_path):
            return True
        return False

    def get_object_metadata(self, storage_path: str) -> Dict[str, Any]:
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        if self.primary and self.primary.file_exists(clean_path):
            meta = self.primary.get_object_metadata(clean_path)
            meta["active_provider"] = self.primary.get_storage_name()
            return meta
        if self.secondary and self.secondary.file_exists(clean_path):
            meta = self.secondary.get_object_metadata(clean_path)
            meta["active_provider"] = self.secondary.get_storage_name()
            return meta
        raise StorageNotFoundError(f"Object '{storage_path}' not found on any active provider.")

    def get_storage_name(self) -> str:
        prim_name = self.primary.get_storage_name() if self.primary else "None"
        sec_name = self.secondary.get_storage_name() if self.secondary else "None"
        return f"Multi-Cloud Router (Primary: {prim_name} | Secondary: {sec_name})"

    def get_capabilities(self) -> Dict[str, Any]:
        prim_caps = self.primary.get_capabilities() if self.primary else {}
        sec_caps = self.secondary.get_capabilities() if self.secondary else {}
        return {
            "provider": "multi_cloud_router",
            "display_name": "CloudVault Intelligent Multi-Cloud Storage Router",
            "primary": prim_caps,
            "secondary": sec_caps,
            "failover_enabled": self.failover_enabled,
            "max_retries": self.max_retries,
            "features": {
                "streaming_upload": True,
                "streaming_download": True,
                "multi_cloud_failover": self.failover_enabled,
                "cross_cloud_migration": True,
                "worm_retention": True,
                "encryption_at_rest": True
            }
        }

    def health_check(self) -> Dict[str, Any]:
        prim_h = self.primary.health_check() if self.primary else {"status": "UNAVAILABLE", "latency_ms": -1}
        sec_h = self.secondary.health_check() if self.secondary else {"status": "NOT_CONFIGURED", "latency_ms": 0}

        overall_status = "HEALTHY"
        if prim_h.get("status") != "HEALTHY":
            overall_status = "DEGRADED" if sec_h.get("status") == "HEALTHY" else "UNAVAILABLE"

        return {
            "status": overall_status,
            "provider": "multi_cloud_router",
            "primary_health": prim_h,
            "secondary_health": sec_h,
            "failover_ready": (sec_h.get("status") == "HEALTHY"),
            "failover_events_count": self.telemetry["failover_events_count"]
        }

    def migrate_object(
        self,
        storage_path: str,
        from_provider: StorageProvider,
        to_provider: StorageProvider,
        delete_source: bool = False
    ) -> Dict[str, Any]:
        """
        Safely migrate a storage object between providers with bit-for-bit SHA-256 verification.
        Does not delete from source until target integrity is cryptographically proven.
        """
        clean_path = storage_path.lstrip("/\\").replace("\\", "/")
        if not from_provider.file_exists(clean_path):
            raise StorageNotFoundError(f"Source object '{storage_path}' not found on {from_provider.get_storage_name()}")

        data = from_provider.download_bytes(clean_path)
        sha256 = hashlib.sha256(data).hexdigest()

        # Upload to target
        to_provider.upload_bytes(data, clean_path)

        # Verify integrity on target
        target_check = to_provider.verify_object_integrity(clean_path, expected_sha256=sha256)
        if not target_check.get("verified"):
            raise StorageIntegrityError(f"Migration integrity check failed on target provider for '{clean_path}'.")

        # Copy retention lock if present
        source_retention = from_provider.get_retention(clean_path)
        if source_retention and source_retention.get("is_active"):
            to_provider.set_retention(
                clean_path,
                datetime.fromisoformat(source_retention["retain_until"]),
                mode=source_retention.get("mode", "COMPLIANCE")
            )

        if delete_source:
            from_provider.delete_file(clean_path)

        return {
            "storage_path": clean_path,
            "from_provider": from_provider.get_storage_name(),
            "to_provider": to_provider.get_storage_name(),
            "bytes_transferred": len(data),
            "sha256": sha256,
            "verified": True,
            "source_deleted": delete_source,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def migrate_snapshot(
        self,
        snapshot_id: str,
        from_provider: StorageProvider,
        to_provider: StorageProvider,
        db: Session,
        delete_source: bool = False
    ) -> Dict[str, Any]:
        """
        Migrate all storage objects belonging to a snapshot between providers,
        updating database records and ensuring zero downtime.
        """
        from backend.app.models import Snapshot, SnapshotFile, StorageObject

        snap = db.query(Snapshot).filter(Snapshot.id == snapshot_id).first()
        if not snap:
            raise ValueError(f"Snapshot '{snapshot_id}' not found.")

        files = db.query(SnapshotFile).filter(SnapshotFile.snapshot_id == snapshot_id).all()
        migrated_objects = []
        total_bytes = 0

        for sf in files:
            so = sf.storage_object
            if not so:
                continue

            clean_path = so.storage_path
            # Migrate object
            res = self.migrate_object(clean_path, from_provider, to_provider, delete_source=delete_source)

            # Update DB reference
            target_name = "mock"
            caps = to_provider.get_capabilities()
            if caps.get("provider"):
                target_name = caps["provider"]

            so.storage_provider = target_name
            db.add(so)
            migrated_objects.append(clean_path)
            total_bytes += res["bytes_transferred"]

        db.commit()

        return {
            "snapshot_id": snapshot_id,
            "files_migrated": len(migrated_objects),
            "total_bytes_migrated": total_bytes,
            "from_provider": from_provider.get_storage_name(),
            "to_provider": to_provider.get_storage_name(),
            "verified": True
        }
