from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models import User, DRDrill
from backend.app.auth import get_current_user
from backend.app.storage import get_storage_provider
from backend.app.services.dr_service import get_dr_metrics, run_synthetic_recovery_drill

router = APIRouter(prefix="/api/v1/dr", tags=["Disaster Recovery Center"])

class SimulateDrillRequest(BaseModel):
    snapshot_id: Optional[str] = None

@router.get("/metrics")
def dr_metrics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve live calculated RPO, measured RTO, and recovery readiness score."""
    return get_dr_metrics(current_user.id, db)

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

