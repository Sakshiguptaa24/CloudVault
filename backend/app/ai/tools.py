import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.models import (
    User, BackupPlan, Snapshot, SnapshotFile, StorageObject, BackupJob,
    RansomwareAlert, AuditLog
)
from backend.app.ai.security import create_confirmation_token

# =====================================================================
# READ-ONLY METADATA QUERY TOOLS
# =====================================================================

def tool_get_protected_files_summary(user_id: str, db: Session) -> Dict[str, Any]:
    """Retrieve total protected files and logical size for authenticated user."""
    total_files = db.query(SnapshotFile).join(Snapshot).filter(
        Snapshot.user_id == user_id,
        SnapshotFile.is_deleted == False
    ).count()

    plans_count = db.query(BackupPlan).filter(BackupPlan.user_id == user_id, BackupPlan.is_active == True).count()
    snapshots_count = db.query(Snapshot).filter(Snapshot.user_id == user_id).count()

    return {
        "status": "success",
        "protected_files_count": total_files,
        "active_plans_count": plans_count,
        "total_snapshots_count": snapshots_count
    }

def tool_get_recent_snapshots(user_id: str, db: Session, limit: int = 5) -> Dict[str, Any]:
    """List recent backup snapshots with timestamps, files, and stored bytes."""
    snaps = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).limit(limit).all()
    results = []
    for s in snaps:
        results.append({
            "snapshot_id": s.id,
            "snapshot_number": s.snapshot_number,
            "name": s.name,
            "created_at": s.created_at.isoformat(),
            "total_files": s.total_files,
            "uncompressed_bytes": s.total_uncompressed_bytes,
            "stored_bytes": s.total_stored_bytes,
            "is_locked": s.is_locked,
            "is_immutable": s.is_immutable,
            "verification_status": s.verification_status
        })
    return {
        "status": "success",
        "count": len(results),
        "snapshots": results
    }

def tool_get_failed_backups(user_id: str, db: Session, days: int = 7) -> Dict[str, Any]:
    """Identify failed or interrupted backup jobs in the past N days."""
    since = datetime.utcnow() - timedelta(days=days)
    failed_jobs = db.query(BackupJob).filter(
        BackupJob.user_id == user_id,
        BackupJob.status.in_(["FAILED", "INTERRUPTED"]),
        BackupJob.started_at >= since
    ).order_by(BackupJob.started_at.desc()).all()

    results = []
    for j in failed_jobs:
        results.append({
            "job_id": j.id,
            "plan_id": j.plan_id,
            "status": j.status,
            "started_at": j.started_at.isoformat(),
            "trigger_type": j.trigger_type,
            "error_message": j.error_message or "Unknown failure"
        })
    return {
        "status": "success",
        "failed_count": len(results),
        "period_days": days,
        "failed_jobs": results
    }

def tool_get_storage_savings(user_id: str, db: Session) -> Dict[str, Any]:
    """Calculate deduplication and compression savings."""
    objs = db.query(StorageObject).filter(StorageObject.user_id == user_id).all()
    total_physical_stored = sum(o.compressed_size for o in objs)
    
    # Logical size is the sum of all snapshot files references
    logical_size = db.query(func.sum(SnapshotFile.file_size)).join(Snapshot).filter(
        Snapshot.user_id == user_id,
        SnapshotFile.is_deleted == False
    ).scalar() or 0

    bytes_saved = max(0, logical_size - total_physical_stored)
    savings_pct = (bytes_saved / logical_size * 100) if logical_size > 0 else 0.0

    return {
        "status": "success",
        "logical_uncompressed_bytes": logical_size,
        "physical_stored_bytes": total_physical_stored,
        "bytes_saved": bytes_saved,
        "savings_percentage": round(savings_pct, 1),
        "unique_storage_objects": len(objs)
    }

def tool_get_unprotected_files(user_id: str, db: Session) -> Dict[str, Any]:
    """Identify local files that have been modified or created since the last backup."""
    plans = db.query(BackupPlan).filter(BackupPlan.user_id == user_id, BackupPlan.is_active == True).all()
    unprotected = []

    for plan in plans:
        latest_snap = db.query(Snapshot).filter(Snapshot.plan_id == plan.id).order_by(Snapshot.created_at.desc()).first()
        import json
        try:
            dirs = json.loads(plan.source_directories)
        except Exception:
            dirs = []

        for d in dirs:
            if not os.path.exists(d):
                continue
            for root, _, files in os.walk(d):
                for f in files:
                    full = os.path.join(root, f)
                    try:
                        mtime = datetime.utcfromtimestamp(os.path.getmtime(full))
                        if not latest_snap or mtime > latest_snap.created_at:
                            unprotected.append({
                                "plan_name": plan.plan_name,
                                "file_path": full,
                                "modified_at": mtime.isoformat()
                            })
                    except Exception:
                        pass
                if len(unprotected) >= 10: # Cap for query brevity
                    break

    return {
        "status": "success",
        "unprotected_sample_count": len(unprotected),
        "unprotected_files": unprotected[:10]
    }

def tool_explain_security_alerts(user_id: str, db: Session) -> Dict[str, Any]:
    """Explain latest active ransomware or anomalous file activity alerts."""
    alerts = db.query(RansomwareAlert).filter(
        RansomwareAlert.user_id == user_id,
        RansomwareAlert.status == "ACTIVE"
    ).order_by(RansomwareAlert.created_at.desc()).limit(5).all()

    results = []
    for a in alerts:
        results.append({
            "alert_id": a.id,
            "risk_score": a.risk_score,
            "alert_level": a.alert_level,
            "suspicious_files_count": a.suspicious_files_count,
            "average_entropy": round(a.average_entropy, 2),
            "matched_extensions": a.matched_extensions,
            "detected_at": a.created_at.isoformat()
        })
    return {
        "status": "success",
        "active_alerts_count": len(results),
        "alerts": results
    }

def tool_check_system_health(user_id: str, db: Session) -> Dict[str, Any]:
    """Evaluate overall system health score and operational metrics."""
    latest_snap = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).first()
    failed_recent = db.query(BackupJob).filter(
        BackupJob.user_id == user_id,
        BackupJob.status == "FAILED",
        BackupJob.started_at >= datetime.utcnow() - timedelta(days=3)
    ).count()

    active_alerts = db.query(RansomwareAlert).filter(
        RansomwareAlert.user_id == user_id,
        RansomwareAlert.status == "ACTIVE"
    ).count()

    # Calculate Backup Health Score (0 - 100)
    score = 100
    if not latest_snap:
        score -= 40
    else:
        hours_since = (datetime.utcnow() - latest_snap.created_at).total_seconds() / 3600
        if hours_since > 48:
            score -= 25
        elif hours_since > 24:
            score -= 10

    if failed_recent > 0:
        score -= min(30, failed_recent * 10)

    if active_alerts > 0:
        score -= min(40, active_alerts * 20)

    score = max(0, min(100, score))

    health_status = "HEALTHY" if score >= 80 else ("WARNING" if score >= 50 else "CRITICAL")

    return {
        "status": "success",
        "health_score": score,
        "health_status": health_status,
        "latest_backup_time": latest_snap.created_at.isoformat() if latest_snap else None,
        "recent_failures_count": failed_recent,
        "active_security_alerts_count": active_alerts
    }

def tool_get_backup_recommendations(user_id: str, db: Session) -> Dict[str, Any]:
    """Provide intelligent recommendations based on user's actual backup history."""
    recs = []
    plans = db.query(BackupPlan).filter(BackupPlan.user_id == user_id, BackupPlan.is_active == True).all()

    if not plans:
        recs.append("You have no active backup plans. Create a plan to protect your important work folders.")
    else:
        for p in plans:
            if p.schedule_type == "manual":
                recs.append(f"Plan '{p.plan_name}' is set to Manual. Consider scheduling interval backups (e.g. every 3600s) to minimize data loss risk.")
            if not p.encryption_enabled:
                recs.append(f"Plan '{p.plan_name}' has encryption disabled. Enable AES-256-GCM encryption for zero-trust protection.")

    latest_snap = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).first()
    if latest_snap and (datetime.utcnow() - latest_snap.created_at).total_seconds() > 86400:
        recs.append("Your latest snapshot is over 24 hours old. Execute a backup now to capture recent file modifications.")

    return {
        "status": "success",
        "recommendations_count": len(recs),
        "recommendations": recs
    }

# =====================================================================
# CONTROLLED ACTION PROPOSAL TOOLS (REQUIRE EXPLICIT CONFIRMATION)
# =====================================================================

def tool_propose_trigger_backup(user_id: str, plan_id: Optional[str], db: Session) -> Dict[str, Any]:
    """Propose triggering an immediate backup for a plan. Requires user confirmation."""
    plan = None
    if plan_id:
        plan = db.query(BackupPlan).filter(BackupPlan.id == plan_id, BackupPlan.user_id == user_id).first()
    if not plan:
        plan = db.query(BackupPlan).filter(BackupPlan.user_id == user_id, BackupPlan.is_active == True).first()

    if not plan:
        return {"status": "error", "message": "No active backup plan found for this user."}

    payload = {
        "plan_id": plan.id,
        "plan_name": plan.plan_name,
        "action": "TRIGGER_BACKUP",
        "description": f"Execute backup plan '{plan.plan_name}' now to create a new point-in-time snapshot."
    }

    token, token_meta = create_confirmation_token(user_id, "TRIGGER_BACKUP", plan.id, payload, db)

    return {
        "status": "requires_confirmation",
        "action_type": "TRIGGER_BACKUP",
        "confirmation_token": token,
        "expires_in_seconds": 300,
        "proposed_action": payload
    }

def tool_propose_restore_file(
    user_id: str,
    snapshot_id: Optional[str] = None,
    relative_path: Optional[str] = None,
    destination_dir: Optional[str] = None,
    db: Session = None
) -> Dict[str, Any]:
    """Propose restoring a file. Requires user confirmation."""
    if not destination_dir:
        destination_dir = "./restored"

    # If specific snapshot not provided, find the most recent snapshot containing files
    if snapshot_id:
        snap = db.query(Snapshot).filter(Snapshot.id == snapshot_id, Snapshot.user_id == user_id).first()
    else:
        snap = db.query(Snapshot).join(SnapshotFile).filter(
            Snapshot.user_id == user_id,
            SnapshotFile.is_deleted == False
        ).order_by(Snapshot.created_at.desc()).first()
        if not snap:
            snap = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).first()

    if not snap:
        return {"status": "error", "message": "No snapshots available to restore from. Please run a backup first."}

    file_entry = None
    if relative_path:
        file_entry = db.query(SnapshotFile).filter(
            SnapshotFile.snapshot_id == snap.id,
            SnapshotFile.relative_path == relative_path,
            SnapshotFile.is_deleted == False
        ).first()
        if not file_entry:
            clean_name = os.path.basename(relative_path).lower()
            file_entry = db.query(SnapshotFile).filter(
                SnapshotFile.snapshot_id == snap.id,
                func.lower(SnapshotFile.file_name) == clean_name,
                SnapshotFile.is_deleted == False
            ).first()

    if not file_entry:
        file_entry = db.query(SnapshotFile).filter(
            SnapshotFile.snapshot_id == snap.id,
            SnapshotFile.is_deleted == False
        ).order_by(SnapshotFile.modified_at.desc()).first()

    if not file_entry:
        return {"status": "error", "message": f"No files found in snapshot #{snap.snapshot_number} ({snap.name}) to restore."}

    target_rel_path = file_entry.relative_path
    payload = {
        "snapshot_id": snap.id,
        "snapshot_number": snap.snapshot_number,
        "snapshot_name": snap.name,
        "relative_path": target_rel_path,
        "file_name": file_entry.file_name,
        "file_size": file_entry.file_size,
        "destination_dir": destination_dir,
        "action": "RESTORE_FILE",
        "description": f"Restore '{file_entry.file_name}' ({round(file_entry.file_size / 1024, 1)} KB) from Snapshot #{snap.snapshot_number} to '{destination_dir}' with SHA-256 verification."
    }

    token, token_meta = create_confirmation_token(user_id, "RESTORE_FILE", snap.id, payload, db)

    return {
        "status": "requires_confirmation",
        "action_type": "RESTORE_FILE",
        "confirmation_token": token,
        "expires_in_seconds": 300,
        "proposed_action": payload
    }

def tool_propose_verify_snapshot(user_id: str, snapshot_id: Optional[str], db: Session) -> Dict[str, Any]:
    """Propose running synthetic recovery drill to verify snapshot integrity."""
    if snapshot_id:
        snap = db.query(Snapshot).filter(Snapshot.id == snapshot_id, Snapshot.user_id == user_id).first()
    else:
        snap = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).first()

    if not snap:
        return {"status": "error", "message": "No snapshots available to verify. Please run a backup first."}

    payload = {
        "snapshot_id": snap.id,
        "snapshot_number": snap.snapshot_number,
        "snapshot_name": snap.name,
        "action": "VERIFY_SNAPSHOT",
        "description": f"Execute synthetic recovery drill to verify bit-level SHA-256 integrity for Snapshot #{snap.snapshot_number} ({snap.name})."
    }

    token, token_meta = create_confirmation_token(user_id, "VERIFY_SNAPSHOT", snap.id, payload, db)

    return {
        "status": "requires_confirmation",
        "action_type": "VERIFY_SNAPSHOT",
        "confirmation_token": token,
        "expires_in_seconds": 300,
        "proposed_action": payload
    }

def tool_propose_lock_snapshot(user_id: str, snapshot_id: str, retention_days: int, db: Session) -> Dict[str, Any]:
    """Propose applying WORM immutable retention lock to snapshot. Requires user confirmation."""
    snap = db.query(Snapshot).filter(Snapshot.id == snapshot_id, Snapshot.user_id == user_id).first()
    if not snap:
        return {"status": "error", "message": "Snapshot not found or does not belong to user."}

    lock_until = datetime.utcnow() + timedelta(days=retention_days)
    payload = {
        "snapshot_id": snap.id,
        "snapshot_name": snap.name,
        "retention_days": retention_days,
        "lock_until": lock_until.isoformat(),
        "action": "LOCK_SNAPSHOT",
        "description": f"Enforce WORM immutable retention on Snapshot '{snap.name}' until {lock_until.strftime('%Y-%m-%d %H:%M UTC')}. It cannot be deleted or modified until this date."
    }

    token, token_meta = create_confirmation_token(user_id, "LOCK_SNAPSHOT", snap.id, payload, db)

    return {
        "status": "requires_confirmation",
        "action_type": "LOCK_SNAPSHOT",
        "confirmation_token": token,
        "expires_in_seconds": 300,
        "proposed_action": payload
    }

