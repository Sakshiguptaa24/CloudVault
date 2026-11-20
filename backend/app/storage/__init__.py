import logging
from typing import Dict, Any, Optional
from backend.app.config import settings
from backend.app.storage.base import StorageProvider
from backend.app.storage.mock_storage import MockStorageProvider
from backend.app.storage.router import MultiCloudRouter
from backend.app.storage.exceptions import (
    StorageError,
    StorageNotFoundError,
    StorageRetentionLockError,
    StorageAuthenticationError,
    StorageTimeoutError,
    StorageIntegrityError,
    StorageQuotaExceededError
)

logger = logging.getLogger("cloudvault.storage")

_storage_instance: Optional[StorageProvider] = None
_router_instance: Optional[MultiCloudRouter] = None

def get_storage_provider(provider_type: Optional[str] = None) -> StorageProvider:
    """
    Factory function returning the active or requested StorageProvider.
    Defaults to settings.STORAGE_PROVIDER (mock, gcs, s3, azure).
    """
    global _storage_instance

    if provider_type is None and _storage_instance is not None:
        return _storage_instance

    target = (provider_type or settings.STORAGE_PROVIDER).lower().strip()

    if target == "gcs":
        try:
            from backend.app.storage.gcs_storage import GCSStorageProvider
            inst = GCSStorageProvider()
            logger.info(f"Initialized Google Cloud Storage Provider on bucket: {settings.GCS_BUCKET_NAME}")
            if provider_type is None:
                _storage_instance = inst
            return inst
        except Exception as e:
            logger.warning(
                f"Could not connect to Google Cloud Storage ({e}). "
                "Falling back to Local Mock Storage Provider for safe offline operation."
            )
            inst = MockStorageProvider()
            if provider_type is None:
                _storage_instance = inst
            return inst

    elif target == "s3":
        try:
            from backend.app.storage.s3_storage import S3StorageProvider
            inst = S3StorageProvider()
            if provider_type is None:
                _storage_instance = inst
            return inst
        except Exception as e:
            logger.warning(f"Could not connect to AWS S3 ({e}). Using simulated mode.")
            inst = S3StorageProvider(simulated=True)
            if provider_type is None:
                _storage_instance = inst
            return inst

    elif target == "azure":
        try:
            from backend.app.storage.azure_storage import AzureBlobStorageProvider
            inst = AzureBlobStorageProvider()
            if provider_type is None:
                _storage_instance = inst
            return inst
        except Exception as e:
            logger.warning(f"Could not connect to Azure Blob Storage ({e}). Using simulated mode.")
            inst = AzureBlobStorageProvider(simulated=True)
            if provider_type is None:
                _storage_instance = inst
            return inst

    # Default to Local Mock Storage Provider
    inst = MockStorageProvider()
    if provider_type is None:
        _storage_instance = inst
    return inst

def get_storage_router(
    primary_type: Optional[str] = None,
    secondary_type: Optional[str] = None
) -> MultiCloudRouter:
    """
    Factory function returning the MultiCloudRouter instance configured with
    primary and secondary failover providers.
    """
    global _router_instance
    prim_type = primary_type or settings.STORAGE_PROVIDER
    sec_type = secondary_type or getattr(settings, "STORAGE_SECONDARY_PROVIDER", "s3")

    primary = get_storage_provider(prim_type)
    secondary = get_storage_provider(sec_type) if sec_type and sec_type.lower() != "none" else None

    if _router_instance is None or primary_type is not None:
        _router_instance = MultiCloudRouter(
            primary_provider=primary,
            secondary_provider=secondary,
            max_retries=getattr(settings, "STORAGE_MAX_RETRIES", 3),
            retry_backoff=getattr(settings, "STORAGE_RETRY_BACKOFF", 0.5),
            failover_enabled=getattr(settings, "STORAGE_FAILOVER_ENABLED", True)
        )
    return _router_instance

def get_multi_cloud_inventory() -> Dict[str, Any]:
    """Retrieve capabilities, routing telemetry, and health check across all supported cloud adapters."""
    from backend.app.storage.s3_storage import S3StorageProvider
    from backend.app.storage.azure_storage import AzureBlobStorageProvider
    from backend.app.storage.gcs_storage import GCSStorageProvider

    active = get_storage_provider()
    router = get_storage_router()

    # Assess individual adapters
    gcs_adapter = GCSStorageProvider(simulated=True)
    s3_adapter = S3StorageProvider(simulated=True)
    azure_adapter = AzureBlobStorageProvider(simulated=True)
    mock_adapter = MockStorageProvider()

    # Health checks
    gcs_health = gcs_adapter.health_check()
    s3_health = s3_adapter.health_check()
    azure_health = azure_adapter.health_check()
    mock_health = mock_adapter.health_check()

    return {
        "active_provider": active.get_storage_name(),
        "active_capabilities": active.get_capabilities(),
        "active_health": active.health_check(),
        "routing": {
            "primary": router.primary.get_storage_name() if router.primary else "None",
            "secondary": router.secondary.get_storage_name() if router.secondary else "None",
            "failover_enabled": router.failover_enabled,
            "max_retries": router.max_retries,
            "failover_events_count": router.telemetry.get("failover_events_count", 0),
            "failover_log": router.telemetry.get("failover_log", [])
        },
        "supported_clouds": {
            "gcs": {
                "name": "Google Cloud Storage",
                "status": "ACTIVE" if "Google" in active.get_storage_name() else "AVAILABLE",
                "simulated": gcs_adapter.simulated,
                "health": gcs_health,
                "tiering": ["STANDARD", "NEARLINE", "COLDLINE", "ARCHIVE"],
                "pricing_per_gb_month": {"STANDARD": 0.020, "NEARLINE": 0.010, "COLDLINE": 0.004, "ARCHIVE": 0.0012}
            },
            "aws_s3": {
                "name": "Amazon S3",
                "status": "READY" if not s3_adapter.simulated else "SIMULATED",
                "simulated": s3_adapter.simulated,
                "health": s3_health,
                "tiering": s3_adapter.get_capabilities()["features"]["tiering"],
                "pricing_per_gb_month": {"STANDARD": 0.023, "INTELLIGENT_TIERING": 0.023, "GLACIER": 0.004, "DEEP_ARCHIVE": 0.00099}
            },
            "azure_blob": {
                "name": "Microsoft Azure Blob",
                "status": "READY" if not azure_adapter.simulated else "SIMULATED",
                "simulated": azure_adapter.simulated,
                "health": azure_health,
                "tiering": azure_adapter.get_capabilities()["features"]["tiering"],
                "pricing_per_gb_month": {"HOT": 0.018, "COOL": 0.010, "COLD": 0.0036, "ARCHIVE": 0.00099}
            },
            "local_mock": {
                "name": "Local Air-Gapped Mock",
                "status": "ACTIVE" if "Mock" in active.get_storage_name() else "STANDBY",
                "simulated": True,
                "health": mock_health,
                "tiering": ["STANDARD", "COLD_SIMULATED"],
                "pricing_per_gb_month": {"STANDARD": 0.000, "COLD_SIMULATED": 0.000}
            }
        },
        "telemetry": router.telemetry,
        "cost_estimation_disclaimer": "Cost estimations are modeled from published cloud vendor pricing metrics and do not represent direct cloud invoices."
    }
