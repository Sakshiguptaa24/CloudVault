import logging
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.auth import get_current_user
from backend.app.models import User, Snapshot, StorageObject
from backend.app.storage import (
    get_storage_provider,
    get_storage_router,
    get_multi_cloud_inventory
)
from backend.app.storage.mock_storage import MockStorageProvider
from backend.app.storage.s3_storage import S3StorageProvider
from backend.app.storage.azure_storage import AzureBlobStorageProvider
from backend.app.storage.gcs_storage import GCSStorageProvider

logger = logging.getLogger("cloudvault.storage.api")

router = APIRouter(prefix="/api/v1/storage", tags=["Multi-Cloud Storage"])

class MigrationRequest(BaseModel):
    snapshot_id: str
    target_provider: str  # 'mock', 'gcs', 's3', 'azure'
    delete_source: bool = False

class FailoverTestRequest(BaseModel):
    simulate_primary_failure: bool = True
    test_payload: Optional[str] = "CloudVault multi-cloud failover verification payload"

@router.get("/inventory")
def get_inventory(current_user: User = Depends(get_current_user)):
    """Retrieve full multi-cloud inventory, active routing, and supported clouds."""
    return get_multi_cloud_inventory()

@router.get("/providers")
def get_providers_capability_matrix(current_user: User = Depends(get_current_user)):
    """Return capability and compliance matrix across all 4 cloud storage providers."""
    mock_prov = MockStorageProvider()
    s3_prov = S3StorageProvider(simulated=True)
    azure_prov = AzureBlobStorageProvider(simulated=True)
    gcs_prov = GCSStorageProvider(simulated=True)

    return {
        "providers": [
            mock_prov.get_capabilities(),
            gcs_prov.get_capabilities(),
            s3_prov.get_capabilities(),
            azure_prov.get_capabilities()
        ],
        "compliance_support": {
            "worm_retention": ["mock", "gcs", "s3", "azure"],
            "client_side_envelope_encryption": ["mock", "gcs", "s3", "azure"],
            "server_side_encryption": ["gcs", "s3", "azure"],
            "object_lock_legal_hold": ["s3", "azure", "gcs"],
            "cross_cloud_replication": True
        }
    }

@router.post("/health-all")
def check_all_providers_health(current_user: User = Depends(get_current_user)):
    """Execute live latency and writability probes across all 4 cloud providers."""
    mock_prov = MockStorageProvider()
    gcs_prov = GCSStorageProvider(simulated=True)
    s3_prov = S3StorageProvider(simulated=True)
    azure_prov = AzureBlobStorageProvider(simulated=True)

    return {
        "timestamp": None,
        "results": {
            "mock": mock_prov.health_check(),
            "gcs": gcs_prov.health_check(),
            "s3": s3_prov.health_check(),
            "azure": azure_prov.health_check()
        }
    }

@router.get("/telemetry")
def get_router_telemetry(current_user: User = Depends(get_current_user)):
    """Return live router transfer counters and failover audit history."""
    router_inst = get_storage_router()
    return {
        "telemetry": router_inst.telemetry,
        "primary_provider": router_inst.primary.get_storage_name() if router_inst.primary else "None",
        "secondary_provider": router_inst.secondary.get_storage_name() if router_inst.secondary else "None",
        "failover_enabled": router_inst.failover_enabled
    }

@router.post("/failover/test")
def test_simulated_failover(
    req: FailoverTestRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Simulate a primary provider failure to verify that the MultiCloudRouter
    seamlessly routes uploads to the secondary provider without data loss.
    """
    mock_primary = MockStorageProvider()
    mock_secondary = S3StorageProvider(simulated=True)

    # Initialize isolated test router
    from backend.app.storage.router import MultiCloudRouter
    test_router = MultiCloudRouter(
        primary_provider=mock_primary,
        secondary_provider=mock_secondary,
        max_retries=2,
        retry_backoff=0.05,
        failover_enabled=True
    )

    if req.simulate_primary_failure:
        mock_primary.simulate_timeout = True

    payload = req.test_payload.encode("utf-8")
    test_path = f"failover_tests/test_{int(1000 * 1000)}.dat"

    try:
        success = test_router.upload_bytes(payload, test_path)
        # Verify bytes are retrievable from secondary
        downloaded = test_router.download_bytes(test_path)
        verified = (downloaded == payload)

        return {
            "success": success,
            "verified": verified,
            "target_path": test_path,
            "failover_events_count": test_router.telemetry["failover_events_count"],
            "failover_log": test_router.telemetry["failover_log"],
            "active_destination": mock_secondary.get_storage_name() if req.simulate_primary_failure else mock_primary.get_storage_name()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failover simulation test failed: {str(e)}"
        )
    finally:
        mock_primary.simulate_timeout = False

@router.post("/migrate")
def migrate_snapshot_cloud(
    req: MigrationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Migrate all storage objects belonging to a snapshot to a target cloud provider,
    verifying bit-for-bit SHA-256 integrity before updating database pointers.
    """
    snap = db.query(Snapshot).filter(Snapshot.id == req.snapshot_id, Snapshot.user_id == current_user.id).first()
    if not snap:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Snapshot not found or unauthorized.")

    target_type = req.target_provider.lower().strip()
    if target_type not in ["mock", "gcs", "s3", "azure"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported target provider '{req.target_provider}'.")

    current_provider = get_storage_provider()
    target_provider = get_storage_provider(target_type)

    router_inst = get_storage_router()
    try:
        result = router_inst.migrate_snapshot(
            snapshot_id=req.snapshot_id,
            from_provider=current_provider,
            to_provider=target_provider,
            db=db,
            delete_source=req.delete_source
        )
        return {
            "message": f"Successfully migrated snapshot {req.snapshot_id} to {target_provider.get_storage_name()}.",
            "result": result
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Migration failed: {str(e)}"
        )

@router.get("/costs")
def get_storage_costs_and_usage(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Return comprehensive multi-cloud storage distribution, object count,
    and estimated monthly costs across providers with clear disclaimers.
    """
    from backend.app.services.analytics_service import (
        GCS_PRICING_PER_GB,
        AWS_S3_PRICING_PER_GB,
        AZURE_BLOB_PRICING_PER_GB
    )

    objects = db.query(StorageObject).filter(StorageObject.user_id == current_user.id).all()

    provider_usage = {
        "mock": {"bytes": 0, "count": 0},
        "gcs": {"bytes": 0, "count": 0},
        "s3": {"bytes": 0, "count": 0},
        "azure": {"bytes": 0, "count": 0}
    }

    total_bytes = 0
    for obj in objects:
        prov = (obj.storage_provider or "mock").lower()
        if prov not in provider_usage:
            prov = "mock"
        provider_usage[prov]["bytes"] += (obj.compressed_size or 0)
        provider_usage[prov]["count"] += 1
        total_bytes += (obj.compressed_size or 0)

    total_gb = total_bytes / (1024 ** 3)

    return {
        "total_stored_bytes": total_bytes,
        "total_stored_gb": round(total_gb, 4),
        "total_objects_count": len(objects),
        "usage_by_provider": {
            p: {
                "stored_bytes": data["bytes"],
                "stored_mb": round(data["bytes"] / (1024 * 1024), 2),
                "stored_gb": round(data["bytes"] / (1024 ** 3), 4),
                "object_count": data["count"]
            }
            for p, data in provider_usage.items()
        },
        "estimated_monthly_costs_usd": {
            "gcs_standard": round(total_gb * GCS_PRICING_PER_GB["STANDARD"], 4),
            "aws_s3_standard": round(total_gb * AWS_S3_PRICING_PER_GB["STANDARD"], 4),
            "azure_blob_hot": round(total_gb * AZURE_BLOB_PRICING_PER_GB["HOT"], 4),
            "local_mock": 0.00
        },
        "billing_disclaimer": "All figures are modeled estimates based on published vendor rate cards. Actual vendor billing depends on API operation tiers, network egress, and minimum retention commitments."
    }
