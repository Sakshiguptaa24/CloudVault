import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.models import (
    User, BackupPlan, Snapshot, SnapshotFile, StorageObject, BackupJob, RansomwareAlert
)

# Standard GCS Pricing reference ($/GB/month)
GCS_PRICING_PER_GB = {
    "STANDARD": 0.020,
    "NEARLINE": 0.010,
    "COLDLINE": 0.004,
    "ARCHIVE": 0.0012
}

def get_analytics_overview(user_id: str, db: Session) -> Dict[str, Any]:
    """Compile comprehensive storage and protection metrics for user."""
    user = db.query(User).filter(User.id == user_id).first()
    objs = db.query(StorageObject).filter(StorageObject.user_id == user_id).all()
    
    total_physical_bytes = sum(o.compressed_size for o in objs)
    logical_bytes = db.query(func.sum(SnapshotFile.file_size)).join(Snapshot).filter(
        Snapshot.user_id == user_id,
        SnapshotFile.is_deleted == False
    ).scalar() or 0

    saved_bytes = max(0, logical_bytes - total_physical_bytes)
    dedup_ratio = round((logical_bytes / total_physical_bytes), 2) if total_physical_bytes > 0 else 1.0

    # File type breakdown
    files = db.query(SnapshotFile.file_extension, func.count(SnapshotFile.id), func.sum(SnapshotFile.file_size)).join(Snapshot).filter(
        Snapshot.user_id == user_id,
        SnapshotFile.is_deleted == False
    ).group_by(SnapshotFile.file_extension).all()

    type_breakdown = []
    for ext, count, size in files:
        label = ext.upper().lstrip(".") if ext else "NO_EXT"
        type_breakdown.append({
            "extension": label,
            "count": count,
            "bytes": size or 0
        })
    type_breakdown.sort(key=lambda x: x["bytes"], reverse=True)

    # Cost Estimation
    stored_gb = total_physical_bytes / (1024 ** 3)
    standard_monthly_cost = round(stored_gb * GCS_PRICING_PER_GB["STANDARD"], 4)
    nearline_monthly_cost = round(stored_gb * GCS_PRICING_PER_GB["NEARLINE"], 4)
    saved_monthly_cost = round((saved_bytes / (1024 ** 3)) * GCS_PRICING_PER_GB["STANDARD"], 4)
    saved_pct = round((saved_bytes / logical_bytes) * 100, 1) if logical_bytes > 0 else 0.0

    return {
        "status": "success",
        "quota_bytes": user.quota_bytes if user else 5368709120,
        "physical_stored_bytes": total_physical_bytes,
        "logical_uncompressed_bytes": logical_bytes,
        "bytes_saved": saved_bytes,
        "deduplication_ratio": dedup_ratio,
        "storage_objects_count": len(objs),
        "file_types_breakdown": type_breakdown[:8],
        "file_breakdown": {t["extension"]: {"count": t["count"], "bytes": t["bytes"]} for t in type_breakdown},
        "estimated_cost_usd_monthly": {
            "gcs_standard": standard_monthly_cost,
            "gcs_nearline": nearline_monthly_cost,
            "active_storage_mode": os.environ.get("STORAGE_PROVIDER", "mock").upper()
        },
        "deduplication": {
            "ratio_multiplier": dedup_ratio,
            "space_saved_bytes": saved_bytes,
            "space_saved_percentage": saved_pct
        },
        "cost_estimation": {
            "estimated_monthly_cost_usd": standard_monthly_cost,
            "monthly_cost_saved_usd": saved_monthly_cost
        }
    }

def get_storage_forecast(user_id: str, db: Session, forecast_days: int = 30) -> Dict[str, Any]:
    """
    Compute daily growth rate and forecast future storage needs.
    Uses historical snapshot data over the past 30 days.
    """
    user = db.query(User).filter(User.id == user_id).first()
    quota = user.quota_bytes if user else 5368709120

    # Get snapshots chronologically
    snaps = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.asc()).all()

    if len(snaps) < 2:
        current_stored = snaps[-1].total_stored_bytes if snaps else 0
        return {
            "status": "baseline_estimate",
            "message": "Insufficient historical snapshots (minimum 2 required) for dynamic growth modeling. Providing baseline estimate.",
            "current_stored_bytes": current_stored,
            "daily_growth_bytes": 0,
            "projected_bytes_30d": current_stored,
            "days_until_quota_exhausted": None,
            "forecast_confidence": "LOW (Baseline)"
        }

    first_snap = snaps[0]
    latest_snap = snaps[-1]
    time_delta = (latest_snap.created_at - first_snap.created_at).total_seconds()

    if time_delta <= 0:
        daily_growth = 0
    else:
        days_span = max(1.0, time_delta / 86400.0)
        size_diff = max(0, latest_snap.total_stored_bytes - first_snap.total_stored_bytes)
        daily_growth = size_diff / days_span

    current_stored = latest_snap.total_stored_bytes
    projected_stored = int(current_stored + (daily_growth * forecast_days))

    remaining_quota = max(0, quota - current_stored)
    days_to_quota = int(remaining_quota / daily_growth) if daily_growth > 0 else None

    return {
        "status": "calculated",
        "current_stored_bytes": current_stored,
        "daily_growth_bytes": int(daily_growth),
        "forecast_days": forecast_days,
        "projected_bytes_30d": projected_stored,
        "quota_bytes": quota,
        "days_until_quota_exhausted": days_to_quota,
        "forecast_confidence": "HIGH" if len(snaps) >= 5 else "MEDIUM"
    }

def get_top_large_files(user_id: str, db: Session, limit: int = 10) -> List[Dict[str, Any]]:
    """Identify largest files protected across active snapshots."""
    files = db.query(SnapshotFile).join(Snapshot).filter(
        Snapshot.user_id == user_id,
        SnapshotFile.is_deleted == False
    ).order_by(SnapshotFile.file_size.desc()).limit(limit).all()

    results = []
    seen_paths = set()
    for f in files:
        if f.relative_path in seen_paths:
            continue
        seen_paths.add(f.relative_path)
        results.append({
            "relative_path": f.relative_path,
            "file_name": f.file_name,
            "file_size": f.file_size,
            "snapshot_id": f.snapshot_id,
            "modified_at": f.modified_at.isoformat()
        })
    return results

def calculate_backup_health_score(user_id: str, db: Session) -> Dict[str, Any]:
    """
    Calculate unified Backup Health Score (0 - 100) based on:
    - RPO Recency: Up to 35 pts
    - Job Success Rate: Up to 25 pts
    - Security Posture (Zero active ransomware alerts): Up to 25 pts
    - Deduplication Efficiency: Up to 15 pts
    """
    latest_snap = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).first()
    
    # 1. Recency Points (Max 35)
    rpo_points = 0
    hours_since = None
    if latest_snap:
        hours_since = (datetime.utcnow() - latest_snap.created_at).total_seconds() / 3600
        if hours_since <= 12:
            rpo_points = 35
        elif hours_since <= 24:
            rpo_points = 30
        elif hours_since <= 48:
            rpo_points = 20
        elif hours_since <= 168:
            rpo_points = 10
        else:
            rpo_points = 5

    # 2. Job Success Rate (Max 25)
    recent_jobs = db.query(BackupJob).filter(
        BackupJob.user_id == user_id,
        BackupJob.started_at >= datetime.utcnow() - timedelta(days=14)
    ).all()
    if not recent_jobs:
        job_points = 20
        success_rate = 100.0
    else:
        success_count = sum(1 for j in recent_jobs if j.status == "SUCCESS")
        success_rate = round((success_count / len(recent_jobs)) * 100, 1)
        job_points = int((success_rate / 100.0) * 25)

    # 3. Security & Ransomware Shield (Max 25)
    active_alerts = db.query(RansomwareAlert).filter(
        RansomwareAlert.user_id == user_id,
        RansomwareAlert.status == "ACTIVE"
    ).count()
    if active_alerts == 0:
        security_points = 25
    elif active_alerts == 1:
        security_points = 10
    else:
        security_points = 0

    # 4. Storage Deduplication Efficiency (Max 15)
    overview = get_analytics_overview(user_id, db)
    dedup_ratio = overview["deduplication_ratio"]
    if dedup_ratio >= 1.5:
        dedup_points = 15
    elif dedup_ratio >= 1.1:
        dedup_points = 10
    else:
        dedup_points = 5

    total_score = rpo_points + job_points + security_points + dedup_points
    total_score = max(0, min(100, total_score))

    status = "EXCELLENT" if total_score >= 85 else ("HEALTHY" if total_score >= 70 else ("NEEDS_ATTENTION" if total_score >= 50 else "CRITICAL"))

    return {
        "status": status,
        "rating": status,
        "score": total_score,
        "health_score": total_score,
        "recommendations": [
            "Enable daily automated backups" if hours_since is None or hours_since > 24 else "Backup cadence healthy",
            "Resolve active ransomware alerts" if active_alerts > 0 else "Ransomware shield clean"
        ],
        "breakdown": {
            "rpo_score": rpo_points,
            "job_reliability_score": job_points,
            "security_posture_score": security_points,
            "dedup_efficiency_score": dedup_points
        },
        "components": {
            "rpo_recency_score": rpo_points,
            "hours_since_last_backup": round(hours_since, 1) if hours_since is not None else None,
            "job_reliability_score": job_points,
            "recent_job_success_rate": success_rate,
            "security_shield_score": security_points,
            "active_security_alerts": active_alerts,
            "deduplication_score": dedup_points,
            "deduplication_ratio": dedup_ratio
        }
    }
