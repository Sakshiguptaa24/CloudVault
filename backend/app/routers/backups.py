import json
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models import User, BackupPlan, BackupJob, Snapshot, StorageObject
from backend.app.schemas import (
    BackupPlanCreate, BackupPlanResponse, BackupJobResponse,
    StorageStatsResponse, SnapshotResponse
)
from backend.app.auth import get_current_user
from backend.app.storage import get_storage_provider
from backend.app.services.backup_service import (
    execute_backup_plan, calculate_bytes_sha256, compress_payload
)

router = APIRouter(prefix="/api/v1/backups", tags=["Backups"])

@router.post("/plans", response_model=BackupPlanResponse, status_code=status.HTTP_201_CREATED)
def create_backup_plan(
    plan_in: BackupPlanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    plan = BackupPlan(
        user_id=current_user.id,
        plan_name=plan_in.plan_name,
        source_directories=json.dumps(plan_in.source_directories),
        exclusion_patterns=json.dumps(plan_in.exclusion_patterns or []),
        schedule_type=plan_in.schedule_type,
        schedule_expression=plan_in.schedule_expression,
        retention_days=plan_in.retention_days,
        compression_algo=plan_in.compression_algo,
        is_active=True
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan

@router.get("/plans", response_model=List[BackupPlanResponse])
def list_backup_plans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(BackupPlan).filter(BackupPlan.user_id == current_user.id).all()

@router.post("/plans/{plan_id}/trigger")
def trigger_backup(
    plan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    plan = db.query(BackupPlan).filter(
        BackupPlan.id == plan_id,
        BackupPlan.user_id == current_user.id
    ).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Backup plan not found")

    storage = get_storage_provider()
    try:
        snapshot, job = execute_backup_plan(
            plan_id=plan.id,
            user=current_user,
            db=db,
            storage=storage,
            trigger_type="MANUAL"
        )
        return {
            "status": "SUCCESS",
            "message": "Backup completed successfully",
            "snapshot_id": snapshot.id,
            "snapshot_name": snapshot.name,
            "files_scanned": job.files_scanned,
            "files_uploaded": job.files_uploaded,
            "files_deduplicated": job.files_deduplicated,
            "bytes_uploaded": job.bytes_uploaded,
            "bytes_deduplicated": job.bytes_deduplicated,
            "duration_seconds": job.duration_seconds
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Backup execution failed: {str(e)}")

@router.post("/upload-file")
def upload_file_direct(
    plan_id: str = Form(...),
    relative_path: Optional[str] = Form(None),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Direct file upload endpoint from Web UI with immediate deduplication."""
    plan = db.query(BackupPlan).filter(
        BackupPlan.id == plan_id,
        BackupPlan.user_id == current_user.id
    ).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Backup plan not found")

    content = file.file.read()
    file_size = len(content)
    sha256 = calculate_bytes_sha256(content)
    file_rel_path = relative_path or file.filename

    storage = get_storage_provider()

    # Deduplication check
    existing = db.query(StorageObject).filter(
        StorageObject.user_id == current_user.id,
        StorageObject.sha256_hash == sha256
    ).first()

    was_uploaded = False
    if existing:
        existing.ref_count += 1
        storage_obj = existing
    else:
        compressed = compress_payload(content, plan.compression_algo)
        storage_path = f"objects/{sha256}"
        storage.upload_bytes(compressed, storage_path)

        storage_obj = StorageObject(
            user_id=current_user.id,
            sha256_hash=sha256,
            original_size=file_size,
            compressed_size=len(compressed),
            compression_algo=plan.compression_algo,
            storage_provider=storage.get_storage_name(),
            storage_path=storage_path,
            ref_count=1
        )
        db.add(storage_obj)
        db.flush()
        current_user.used_bytes += len(compressed)
        was_uploaded = True

    # Commit as a snapshot
    from datetime import datetime
    from backend.app.models import SnapshotFile

    last_snap = db.query(Snapshot).filter(
        Snapshot.plan_id == plan.id
    ).order_by(Snapshot.snapshot_number.desc()).first()
    next_num = (last_snap.snapshot_number + 1) if last_snap else 1

    snap = Snapshot(
        plan_id=plan.id,
        user_id=current_user.id,
        snapshot_number=next_num,
        name=f"Upload: {file.filename} (#{next_num})",
        snapshot_type="manual_upload",
        total_files=1,
        total_uncompressed_bytes=file_size,
        total_stored_bytes=storage_obj.compressed_size if was_uploaded else 0
    )
    db.add(snap)
    db.flush()

    s_file = SnapshotFile(
        snapshot_id=snap.id,
        storage_object_id=storage_obj.id,
        relative_path=file_rel_path,
        file_name=file.filename,
        file_extension=Path(file.filename).suffix.lower(),
        file_size=file_size,
        modified_at=datetime.utcnow()
    )
    db.add(s_file)

    # Log Job
    job = BackupJob(
        plan_id=plan.id,
        user_id=current_user.id,
        status="SUCCESS",
        trigger_type="WEB_UPLOAD",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        files_scanned=1,
        files_uploaded=1 if was_uploaded else 0,
        files_deduplicated=0 if was_uploaded else 1,
        bytes_scanned=file_size,
        bytes_uploaded=storage_obj.compressed_size if was_uploaded else 0,
        bytes_deduplicated=0 if was_uploaded else file_size,
        duration_seconds=1
    )
    db.add(job)
    db.commit()

    return {
        "status": "SUCCESS",
        "file_name": file.filename,
        "sha256": sha256,
        "deduplicated": not was_uploaded,
        "bytes_stored": storage_obj.compressed_size if was_uploaded else 0,
        "snapshot_id": snap.id
    }

@router.get("/jobs", response_model=List[BackupJobResponse])
def get_backup_jobs(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(BackupJob).filter(
        BackupJob.user_id == current_user.id
    ).order_by(BackupJob.started_at.desc()).limit(limit).all()

@router.get("/stats", response_model=StorageStatsResponse)
def get_storage_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    storage = get_storage_provider()
    snapshots = db.query(Snapshot).filter(Snapshot.user_id == current_user.id).all()
    plans = db.query(BackupPlan).filter(BackupPlan.user_id == current_user.id).all()
    jobs = db.query(BackupJob).filter(BackupJob.user_id == current_user.id).all()

    total_uncompressed = sum(s.total_uncompressed_bytes for s in snapshots)
    total_stored = current_user.used_bytes
    bytes_saved = max(0, total_uncompressed - total_stored)
    savings_pct = (bytes_saved / total_uncompressed * 100) if total_uncompressed > 0 else 0.0

    return {
        "total_snapshots": len(snapshots),
        "total_files_protected": sum(s.total_files for s in snapshots),
        "total_uncompressed_bytes": total_uncompressed,
        "total_stored_bytes": total_stored,
        "bytes_saved_deduplication": bytes_saved,
        "savings_percentage": round(savings_pct, 2),
        "storage_provider": storage.get_storage_name(),
        "active_plans": len([p for p in plans if p.is_active]),
        "total_backup_jobs": len(jobs)
    }
