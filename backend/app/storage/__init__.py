import logging
from typing import Dict, Any, Optional
from backend.app.config import settings
from backend.app.storage.base import StorageProvider
from backend.app.storage.mock_storage import MockStorageProvider

logger = logging.getLogger("cloudvault.storage")

_storage_instance: Optional[StorageProvider] = None

def get_storage_provider(provider_type: Optional[str] = None) -> StorageProvider:
    """
    Factory function returning the active or requested StorageProvider.
    Defaults to settings.STORAGE_PROVIDER (gcs, s3, azure, or mock).
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

def get_multi_cloud_inventory() -> Dict[str, Any]:
    """Retrieve capabilities and health check across all supported cloud adapters."""
    from backend.app.storage.s3_storage import S3StorageProvider
    from backend.app.storage.azure_storage import AzureBlobStorageProvider

    active = get_storage_provider()
    
    # Assess adapters
    s3_adapter = S3StorageProvider(simulated=True)
    azure_adapter = AzureBlobStorageProvider(simulated=True)

    return {
        "active_provider": active.get_storage_name(),
        "active_capabilities": active.get_capabilities(),
        "active_health": active.health_check(),
        "supported_clouds": {
            "gcs": {
                "name": "Google Cloud Storage",
                "status": "ACTIVE" if "Google" in active.get_storage_name() else "AVAILABLE",
                "tiering": ["STANDARD", "NEARLINE", "COLDLINE", "ARCHIVE"]
            },
            "aws_s3": {
                "name": "Amazon S3",
                "status": "READY" if not s3_adapter.simulated else "SIMULATED",
                "tiering": s3_adapter.get_capabilities()["features"]["tiering"]
            },
            "azure_blob": {
                "name": "Microsoft Azure Blob",
                "status": "READY" if not azure_adapter.simulated else "SIMULATED",
                "tiering": azure_adapter.get_capabilities()["features"]["tiering"]
            },
            "local_mock": {
                "name": "Local Air-Gapped Mock",
                "status": "ACTIVE" if "Mock" in active.get_storage_name() else "STANDBY",
                "tiering": ["STANDARD", "COLD_SIMULATED"]
            }
        }
    }
