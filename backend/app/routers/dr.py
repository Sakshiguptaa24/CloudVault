import json
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models import User, DRDrill, RecoveryOperation
from backend.app.auth import get_current_user
from backend.app.storage import get_storage_provider
from backend.app.services.dr_service import (
    get_dr_metrics,
    run_synthetic_recovery_drill,
    get_dr_command_center_telemetry,
    run_advanced_synthetic_recovery_drill,
    get_point_in_time_preview,
    plan_ransomware_recovery,
    execute_ransomware_recovery,
    run_recovery_sandbox_preview,
    list_recovery_operations
)

router = APIRouter(prefix="/api/v1/dr", tags=["Disaster Recovery Center"])


class SimulateDrillRequest(BaseModel):
    snapshot_id: Optional[str] = None


class AdvancedDrillRequest(BaseModel):
    snapshot_id: Optional[str] = None
    drill_type: str = "FULL_SNAPSHOT"  # FULL_SNAPSHOT, FOLDER, FILE, POINT_IN_TIME, RANSOMWARE_PRE_INCIDENT, CORRUPTED_OBJECT_TEST
    drill_scope: Optional[str] = None
    inject_corruption: bool = False


class RansomwareRecoveryRequest(BaseModel):
    snapshot_id: str
    destination_dir: Optional[str] = None
    conflict_strategy: str = "keep_both"
    confirmed: bool = False


class SandboxPreviewRequest(BaseModel):
    snapshot_id: str
    file_ids: Optional[List[str]] = None


@router.get("/metrics")
def dr_metrics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve live calculated RPO, measured RTO, and recovery readiness score."""
    return get_dr_metrics(current_user.id, db)


@router.get("/command-center")
def dr_command_center(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieve comprehensive Disaster Recovery Command Center telemetry,
    including readiness score breakdown, available recovery points, RPO/RTO metrics,
    active incidents, failed operations, and prioritized recommendations.
    """
    return get_dr_command_center_telemetry(current_user.id, db)


@router.post("/simulate-drill")
def simulate_recovery_drill(
    req: SimulateDrillRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Execute a sandboxed synthetic recovery drill.
    Streams backup blocks, verifies SHA-256 integrity, calculates restoration speed,
    and updates snapshot verification status without touching primary user files.
    """
    storage = get_storage_provider()
    try:
        return run_synthetic_recovery_drill(req.snapshot_id, current_user.id, db, storage)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Disaster recovery drill failed: {str(e)}")


@router.post("/advanced-drill")
def advanced_recovery_drill(
    req: AdvancedDrillRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Execute an advanced synthetic recovery drill across custom scopes:
    FULL_SNAPSHOT, FOLDER, FILE, POINT_IN_TIME, RANSOMWARE_PRE_INCIDENT, or CORRUPTED_OBJECT_TEST.
    Performs bit-for-bit SHA-256 integrity verification, envelope decryption, and produces a detailed report.
    """
    storage = get_storage_provider()
    try:
        return run_advanced_synthetic_recovery_drill(
            user_id=current_user.id,
            db=db,
            storage=storage,
            snapshot_id=req.snapshot_id,
            drill_type=req.drill_type,
            drill_scope=req.drill_scope,
            inject_corruption=req.inject_corruption
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Advanced recovery drill failed: {str(e)}")


@router.get("/drills/{drill_id}/report")
def get_drill_report(
    drill_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve full per-file verification report for a specific recovery drill."""
    drill = db.query(DRDrill).filter(
        DRDrill.id == drill_id,
        DRDrill.user_id == current_user.id
    ).first()
    if not drill:
        raise HTTPException(status_code=404, detail="Drill record not found")

    parsed_report = []
    if drill.verification_report:
        try:
            parsed_report = json.loads(drill.verification_report)
        except Exception:
            parsed_report = []

    return {
        "drill_id": drill.id,
        "snapshot_id": drill.snapshot_id,
        "snapshot_name": drill.snapshot.name if drill.snapshot else "Snapshot",
        "drill_type": getattr(drill, "drill_type", "FULL_SNAPSHOT") or "FULL_SNAPSHOT",
        "drill_scope": getattr(drill, "drill_scope", None),
        "status": drill.status,
        "files_tested": drill.files_tested,
        "bytes_tested": drill.bytes_tested,
        "duration_seconds": drill.duration_seconds,
        "restoration_speed_mbps": drill.restoration_speed_mbps,
        "rpo_hours": drill.rpo_hours,
        "estimated_rto_minutes": drill.estimated_rto_minutes,
        "error_details": drill.error_details,
        "created_at": drill.created_at.isoformat(),
        "verification_report": parsed_report
    }


@router.get("/point-in-time/preview")
def point_in_time_preview(
    snapshot_id: str = Query(...),
    destination_dir: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Inspect snapshot files and preview differences (NEW, MODIFIED, UNCHANGED) against local destination."""
    try:
        return get_point_in_time_preview(
            snapshot_id=snapshot_id,
            destination_dir=destination_dir,
            user_id=current_user.id,
            db=db
        )
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Point-in-time preview failed: {str(e)}")


@router.get("/ransomware-recovery/plan")
def ransomware_recovery_plan(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Intelligently select the last known clean recovery point prior to a ransomware alert,
    excluding suspicious snapshots and explaining why the candidate is safe.
    """
    return plan_ransomware_recovery(current_user.id, db)


@router.post("/ransomware-recovery/execute")
def ransomware_recovery_execute(
    req: RansomwareRecoveryRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Execute disaster recovery from clean baseline into an isolated recovery folder.
    Requires explicit user confirmation before replacing or writing data.
    """
    storage = get_storage_provider()
    try:
        return execute_ransomware_recovery(
            snapshot_id=req.snapshot_id,
            destination_dir=req.destination_dir,
            conflict_strategy=req.conflict_strategy,
            confirmed=req.confirmed,
            user_id=current_user.id,
            db=db,
            storage=storage
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ransomware recovery failed: {str(e)}")


@router.post("/sandbox/preview")
def recovery_sandbox_preview(
    req: SandboxPreviewRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Perform non-destructive recovery into an isolated temporary sandbox.
    Verifies checksums and returns text previews of reconstructed files.
    """
    storage = get_storage_provider()
    try:
        return run_recovery_sandbox_preview(
            snapshot_id=req.snapshot_id,
            file_ids=req.file_ids,
            user_id=current_user.id,
            db=db,
            storage=storage
        )
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sandbox preview failed: {str(e)}")


@router.get("/operations")
def list_operations(
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve history of recovery operations with real measured RTO and RPO metrics."""
    return {"operations": list_recovery_operations(current_user.id, db, limit=limit)}


@router.get("/history")
def dr_history(
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve history of past automated and manual synthetic disaster recovery drills."""
    drills = db.query(DRDrill).filter(
        DRDrill.user_id == current_user.id
    ).order_by(DRDrill.created_at.desc()).limit(limit).all()

    results = []
    for d in drills:
        results.append({
            "drill_id": d.id,
            "snapshot_id": d.snapshot_id,
            "snapshot_name": d.snapshot.name if d.snapshot else "Snapshot",
            "drill_type": getattr(d, "drill_type", "FULL_SNAPSHOT") or "FULL_SNAPSHOT",
            "drill_scope": getattr(d, "drill_scope", None),
            "status": d.status,
            "files_tested": d.files_tested,
            "bytes_tested": d.bytes_tested,
            "duration_seconds": d.duration_seconds,
            "restoration_speed_mbps": d.restoration_speed_mbps,
            "rpo_hours": d.rpo_hours,
            "estimated_rto_minutes": d.estimated_rto_minutes,
            "error_details": d.error_details,
            "created_at": d.created_at.isoformat()
        })
    return {"drills": results, "count": len(results)}


@router.get("/readiness")
def dr_readiness(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Return high-level recovery readiness status for header badge."""
    metrics = get_dr_metrics(current_user.id, db)
    return {
        "readiness_score": metrics["readiness_score"],
        "readiness_level": metrics["readiness_level"],
        "rpo_status": metrics["rpo"]["status"],
        "rpo_hours": metrics["rpo"]["hours"]
    }
