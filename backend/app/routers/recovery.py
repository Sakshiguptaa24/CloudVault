from typing import List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models import User, Snapshot, SnapshotFile, BackupPlan
from backend.app.schemas import (
    SnapshotResponse, SnapshotFileResponse, RestoreFileRequest,
    RestoreSnapshotRequest, RestoreResponse, DeletedFileItem
)
from backend.app.auth import get_current_user
from backend.app.storage import get_storage_provider
from backend.app.services.restore_service import (
    restore_file_by_id, restore_snapshot, get_deleted_files_for_plan
)

router = APIRouter(prefix="/api/v1/recovery", tags=["Recovery & Snapshots"])

@router.get("/snapshots", response_model=List[SnapshotResponse])
def list_snapshots(
    plan_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Snapshot).filter(Snapshot.user_id == current_user.id)
    if plan_id:
        query = query.filter(Snapshot.plan_id == plan_id)
    return query.order_by(Snapshot.created_at.desc()).all()

@router.get("/snapshots/{snapshot_id}/tree", response_model=List[SnapshotFileResponse])
def get_snapshot_tree(
    snapshot_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    snapshot = db.query(Snapshot).filter(
        Snapshot.id == snapshot_id,
        Snapshot.user_id == current_user.id
    ).first()
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    items = []
    for sf in snapshot.files:
        items.append({
            "id": sf.id,
            "relative_path": sf.relative_path,
            "file_name": sf.file_name,
            "file_extension": sf.file_extension or "",
            "file_size": sf.file_size,
            "modified_at": sf.modified_at,
            "sha256_hash": sf.storage_object.sha256_hash if sf.storage_object else "",
            "is_deleted": sf.is_deleted
        })
    return items

@router.post("/restore-file", response_model=RestoreResponse)
def restore_file(
    request: RestoreFileRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    storage = get_storage_provider()
    try:
        result = restore_file_by_id(
            snapshot_file_id=request.snapshot_file_id,
            destination_dir=request.destination_directory,
            conflict_strategy=request.conflict_strategy,
            db=db,
            storage=storage,
            user_id=current_user.id
        )
        return {
            "status": "SUCCESS",
            "message": f"Restored {result['file_name']} successfully with verified integrity.",
            "files_restored": 1 if result["status"] == "RESTORED" else 0,
            "bytes_restored": result["bytes_restored"],
            "destination": result["path"],
            "integrity_verified": True
        }
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File restore failed: {str(e)}")

@router.post("/restore-snapshot", response_model=RestoreResponse)
def restore_entire_snapshot(
    request: RestoreSnapshotRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    storage = get_storage_provider()
    try:
        result = restore_snapshot(
            snapshot_id=request.snapshot_id,
            destination_dir=request.destination_directory,
            conflict_strategy=request.conflict_strategy,
            db=db,
            storage=storage,
            user_id=current_user.id
        )
        return {
            "status": "SUCCESS",
            "message": f"Snapshot restored: {result['files_restored']} files recovered.",
            "files_restored": result["files_restored"],
            "bytes_restored": result["bytes_restored"],
            "destination": result["destination"],
            "integrity_verified": True
        }
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Snapshot restore failed: {str(e)}")

@router.get("/deleted-files", response_model=List[DeletedFileItem])
def get_deleted_files(
    plan_id: str = Query(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve all files that were deleted locally but remain recoverable from past snapshots."""
    plan = db.query(BackupPlan).filter(
        BackupPlan.id == plan_id,
        BackupPlan.user_id == current_user.id
    ).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found or unauthorized")

    return get_deleted_files_for_plan(plan_id, db, user_id=current_user.id)

class LockSnapshotRequest(BaseModel):
    retention_days: int = 30

@router.post("/snapshots/{snapshot_id}/lock")
def lock_snapshot_worm(
    snapshot_id: str,
    req: LockSnapshotRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Enforce WORM (Write Once Read Many) immutable retention policy on snapshot."""
    snap = db.query(Snapshot).filter(
        Snapshot.id == snapshot_id,
        Snapshot.user_id == current_user.id
    ).first()
    if not snap:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    from datetime import datetime, timedelta
    lock_until = datetime.utcnow() + timedelta(days=req.retention_days)
    snap.is_locked = True
    snap.is_immutable = True
    snap.lock_until = lock_until
    db.commit()

    from backend.app.ai.security import record_audit_log
    record_audit_log(
        user_id=current_user.id,
        event_type="SNAPSHOT_WORM_LOCKED",
        action=f"Snapshot #{snap.snapshot_number} locked for {req.retention_days} days",
        details={"snapshot_id": snap.id, "lock_until": lock_until.isoformat()},
        db=db,
        severity="WARNING"
    )

    return {
        "status": "SUCCESS",
        "message": f"WORM immutable retention locked on Snapshot #{snap.snapshot_number} until {lock_until.isoformat()}",
        "snapshot_id": snap.id,
        "is_immutable": True,
        "lock_until": lock_until.isoformat()
    }

@router.delete("/snapshots/{snapshot_id}")
def delete_snapshot(
    snapshot_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a snapshot unless protected by active WORM immutable retention policy."""
    snap = db.query(Snapshot).filter(
        Snapshot.id == snapshot_id,
        Snapshot.user_id == current_user.id
    ).first()
    if not snap:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    from datetime import datetime
    if snap.is_immutable and snap.lock_until and snap.lock_until > datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"WORM Immutable Retention Violation: Snapshot is locked until {snap.lock_until.isoformat()} and cannot be deleted or modified."
        )

    db.delete(snap)
    db.commit()
    return {"status": "SUCCESS", "message": f"Snapshot #{snap.snapshot_number} deleted successfully."}

