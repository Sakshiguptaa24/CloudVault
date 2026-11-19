import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.models import (
    User, BackupPlan, Snapshot, SnapshotFile, StorageObject, BackupJob, RansomwareAlert
)

# Standard Cloud Storage Pricing references ($/GB/month)
GCS_PRICING_PER_GB = {
    "STANDARD": 0.020,
    "NEARLINE": 0.010,
    "COLDLINE": 0.004,
    "ARCHIVE": 0.0012
}

AWS_S3_PRICING_PER_GB = {
    "STANDARD": 0.023,
    "INFREQUENT_ACCESS": 0.0125,
    "GLACIER_FLEXIBLE": 0.004,
    "DEEP_ARCHIVE": 0.00099
}

AZURE_BLOB_PRICING_PER_GB = {
    "HOT": 0.018,
    "COOL": 0.010,
    "COLD": 0.0036,
    "ARCHIVE": 0.00099
}


def get_analytics_overview(user_id: str, db: Session) -> Dict[str, Any]:
    """Compile comprehensive storage, multi-cloud cost models, and protection metrics for user."""
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

    # Multi-Cloud Cost Estimation
    stored_gb = total_physical_bytes / (1024 ** 3)
    saved_gb = saved_bytes / (1024 ** 3)

    gcs_standard_cost = round(stored_gb * GCS_PRICING_PER_GB["STANDARD"], 4)
    gcs_nearline_cost = round(stored_gb * GCS_PRICING_PER_GB["NEARLINE"], 4)
    gcs_saved_cost = round(saved_gb * GCS_PRICING_PER_GB["STANDARD"], 4)
    saved_pct = round((saved_bytes / logical_bytes) * 100, 1) if logical_bytes > 0 else 0.0

    cloud_cost_comparison = {
        "gcs": {
            "provider": "Google Cloud Storage",
            "standard_monthly_usd": gcs_standard_cost,
            "nearline_monthly_usd": gcs_nearline_cost,
            "coldline_monthly_usd": round(stored_gb * GCS_PRICING_PER_GB["COLDLINE"], 4),
            "archive_monthly_usd": round(stored_gb * GCS_PRICING_PER_GB["ARCHIVE"], 4),
            "saved_via_dedup_usd": gcs_saved_cost
        },
        "aws_s3": {
            "provider": "Amazon Web Services S3",
            "standard_monthly_usd": round(stored_gb * AWS_S3_PRICING_PER_GB["STANDARD"], 4),
            "ia_monthly_usd": round(stored_gb * AWS_S3_PRICING_PER_GB["INFREQUENT_ACCESS"], 4),
            "glacier_monthly_usd": round(stored_gb * AWS_S3_PRICING_PER_GB["GLACIER_FLEXIBLE"], 4),
            "deep_archive_monthly_usd": round(stored_gb * AWS_S3_PRICING_PER_GB["DEEP_ARCHIVE"], 4),
            "saved_via_dedup_usd": round(saved_gb * AWS_S3_PRICING_PER_GB["STANDARD"], 4)
        },
        "azure_blob": {
            "provider": "Microsoft Azure Blob Storage",
            "hot_monthly_usd": round(stored_gb * AZURE_BLOB_PRICING_PER_GB["HOT"], 4),
            "cool_monthly_usd": round(stored_gb * AZURE_BLOB_PRICING_PER_GB["COOL"], 4),
            "cold_monthly_usd": round(stored_gb * AZURE_BLOB_PRICING_PER_GB["COLD"], 4),
            "archive_monthly_usd": round(stored_gb * AZURE_BLOB_PRICING_PER_GB["ARCHIVE"], 4),
            "saved_via_dedup_usd": round(saved_gb * AZURE_BLOB_PRICING_PER_GB["HOT"], 4)
        }
    }

    # Cold data analysis (files unmodified for > 90 days)
    ninety_days_ago = datetime.utcnow() - timedelta(days=90)
    cold_files_query = db.query(func.count(SnapshotFile.id), func.sum(SnapshotFile.file_size)).join(Snapshot).filter(
        Snapshot.user_id == user_id,
        SnapshotFile.is_deleted == False,
        SnapshotFile.modified_at < ninety_days_ago
    ).first()

    cold_file_count = cold_files_query[0] or 0
    cold_file_bytes = cold_files_query[1] or 0
    cold_file_gb = cold_file_bytes / (1024 ** 3)
    potential_archive_savings = round(
        (cold_file_gb * GCS_PRICING_PER_GB["STANDARD"]) - (cold_file_gb * GCS_PRICING_PER_GB["ARCHIVE"]), 4
    )

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
            "gcs_standard": gcs_standard_cost,
            "gcs_nearline": gcs_nearline_cost,
            "active_storage_mode": os.environ.get("STORAGE_PROVIDER", "mock").upper()
        },
        "deduplication": {
            "ratio_multiplier": dedup_ratio,
            "space_saved_bytes": saved_bytes,
            "space_saved_percentage": saved_pct
        },
        "cost_estimation": {
            "estimated_monthly_cost_usd": gcs_standard_cost,
            "monthly_cost_saved_usd": gcs_saved_cost
        },
        "cloud_cost_comparison": cloud_cost_comparison,
        "cold_data_summary": {
            "cold_files_count": cold_file_count,
            "cold_bytes": cold_file_bytes,
            "potential_archive_savings_usd": max(0.0, potential_archive_savings),
            "tiering_recommendation": (
                f"Tier {cold_file_count} cold files ({round(cold_file_gb, 2)} GB) to Archive storage to save ~${potential_archive_savings}/mo."
                if cold_file_count > 0 else "All files actively modified within 90 days."
            )
        }
    }


def get_storage_forecast(user_id: str, db: Session, forecast_days: int = 30) -> Dict[str, Any]:
    """
    Compute daily growth rate using linear regression/velocity and forecast multi-window storage needs.
    Returns 7, 14, 30, and 90-day projections along with quota exhaustion timeline.
    """
    user = db.query(User).filter(User.id == user_id).first()
    quota = user.quota_bytes if user else 5368709120

    # Get snapshots chronologically
    snaps = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.asc()).all()

    if len(snaps) < 2:
        current_stored = snaps[-1].total_stored_bytes if snaps else 0
        projections = {
            "day_0_bytes": current_stored,
            "day_7_bytes": current_stored,
            "day_14_bytes": current_stored,
            "day_30_bytes": current_stored,
            "day_90_bytes": current_stored
        }
        return {
            "status": "baseline_estimate",
            "message": "Insufficient historical snapshots (minimum 2 required) for dynamic growth modeling. Providing baseline estimate.",
            "current_stored_bytes": current_stored,
            "daily_growth_bytes": 0,
            "forecast_days": forecast_days,
            "projected_bytes_30d": current_stored,
            "projected_bytes_7d": current_stored,
            "projected_bytes_14d": current_stored,
            "projected_bytes_90d": current_stored,
            "projections": projections,
            "quota_bytes": quota,
            "days_until_quota_exhausted": None,
            "days_to_quota": None,
            "forecast_confidence": "LOW (Baseline)",
            "growth_model": "baseline"
        }

    # If we have 3 or more snapshots, calculate least-squares linear velocity slope
    if len(snaps) >= 3:
        t0 = snaps[0].created_at
        time_points = []
        sizes = []
        for s in snaps:
            days_from_start = (s.created_at - t0).total_seconds() / 86400.0
            time_points.append(days_from_start)
            sizes.append(float(s.total_stored_bytes))

        n = len(time_points)
        t_mean = sum(time_points) / n
        y_mean = sum(sizes) / n

        denom = sum((t - t_mean) ** 2 for t in time_points)
        if denom > 0:
            slope = sum((t - t_mean) * (y - y_mean) for t, y in zip(time_points, sizes)) / denom
        else:
            slope = 0.0

        daily_growth = max(0.0, slope)
        growth_model = "least_squares_linear_regression"
        confidence = "HIGH" if len(snaps) >= 5 else "MEDIUM"
    else:
        # Exactly 2 snapshots: point-to-point velocity
        first_snap = snaps[0]
        latest_snap = snaps[-1]
        time_delta = (latest_snap.created_at - first_snap.created_at).total_seconds()

        if time_delta <= 0:
            daily_growth = 0.0
        else:
            days_span = max(1.0 / 86400.0, time_delta / 86400.0)
            size_diff = max(0, latest_snap.total_stored_bytes - first_snap.total_stored_bytes)
            daily_growth = size_diff / days_span

        growth_model = "point_to_point_velocity"
        confidence = "MEDIUM"

    current_stored = snaps[-1].total_stored_bytes
    day_7 = int(current_stored + (daily_growth * 7))
    day_14 = int(current_stored + (daily_growth * 14))
    day_30 = int(current_stored + (daily_growth * 30))
    day_90 = int(current_stored + (daily_growth * 90))

    projections = {
        "day_0_bytes": current_stored,
        "day_7_bytes": day_7,
        "day_14_bytes": day_14,
        "day_30_bytes": day_30,
        "day_90_bytes": day_90
    }

    if current_stored >= quota:
        days_to_quota = 0
    elif daily_growth > 0:
        remaining_quota = max(0, quota - current_stored)
        days_to_quota = int(remaining_quota / daily_growth)
    else:
        days_to_quota = None

    return {
        "status": "calculated",
        "current_stored_bytes": current_stored,
        "daily_growth_bytes": int(daily_growth),
        "forecast_days": forecast_days,
        "projected_bytes_7d": day_7,
        "projected_bytes_14d": day_14,
        "projected_bytes_30d": day_30,
        "projected_bytes_90d": day_90,
        "projections": projections,
        "quota_bytes": quota,
        "days_until_quota_exhausted": days_to_quota,
        "days_to_quota": days_to_quota,
        "forecast_confidence": confidence,
        "growth_model": growth_model
    }


def get_top_large_files(user_id: str, db: Session, limit: int = 10) -> List[Dict[str, Any]]:
    """Identify largest files protected across active snapshots."""
    files = db.query(SnapshotFile).join(Snapshot).filter(
        Snapshot.user_id == user_id,
        SnapshotFile.is_deleted == False
    ).order_by(SnapshotFile.file_size.desc()).limit(limit * 2).all()

    results = []
    seen_paths = set()
    for f in files:
        if f.relative_path in seen_paths:
            continue
        seen_paths.add(f.relative_path)
        results.append({
            "relative_path": f.relative_path,
            "file_name": f.file_name,
            "file_extension": f.file_extension,
            "file_size": f.file_size,
            "snapshot_id": f.snapshot_id,
            "modified_at": f.modified_at.isoformat()
        })
        if len(results) >= limit:
            break
    return results


def calculate_backup_health_score(user_id: str, db: Session) -> Dict[str, Any]:
    """
    Calculate unified, multi-dimensional Backup Health Score (0 - 100):
    1. RPO Recency: Up to 35 pts (freshness of latest snapshot)
    2. Job Reliability & Success: Up to 30 pts (success rate of jobs over 14 days)
    3. Security & Ransomware Shield: Up to 20 pts (zero active anomalies/alerts)
    4. Deduplication & Storage Efficiency: Up to 15 pts (space optimization ratio)
    """
    latest_snap = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).first()
    recs = []

    # 1. RPO Recency Points (Max 35)
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
            recs.append("Last snapshot was taken over 24 hours ago. Trigger a backup to improve RPO.")
        elif hours_since <= 168:
            rpo_points = 10
            recs.append("Last snapshot is several days old (>48h). Automated daily schedules are advised.")
        else:
            rpo_points = 5
            recs.append("Stale backup posture (>1 week old). Run an immediate backup to avoid data loss.")
    else:
        recs.append("No snapshots recorded yet. Create an active backup plan and take an initial snapshot.")

    # 2. Job Reliability Points (Max 30)
    recent_jobs = db.query(BackupJob).filter(
        BackupJob.user_id == user_id,
        BackupJob.started_at >= datetime.utcnow() - timedelta(days=14)
    ).all()
    if not recent_jobs:
        job_points = 25
        success_rate = 100.0
    else:
        success_count = sum(1 for j in recent_jobs if j.status == "SUCCESS")
        success_rate = round((success_count / len(recent_jobs)) * 100, 1)
        job_points = int((success_rate / 100.0) * 30)
        if success_rate < 80.0:
            failed_count = len(recent_jobs) - success_count
            recs.append(f"{failed_count} backup job(s) failed recently ({success_rate}% success). Inspect failure trends.")

    # 3. Security & Ransomware Shield Points (Max 20)
    active_alerts = db.query(RansomwareAlert).filter(
        RansomwareAlert.user_id == user_id,
        RansomwareAlert.status == "ACTIVE"
    ).count()

    if active_alerts == 0:
        security_points = 20
    elif active_alerts == 1:
        security_points = 8
        recs.append("1 active ransomware alert requires investigation in the Security Center.")
    else:
        security_points = 0
        recs.append(f"{active_alerts} active security anomalies detected! Clean snapshots are protected; resolve alerts.")

    # 4. Storage Deduplication Efficiency Points (Max 15)
    overview = get_analytics_overview(user_id, db)
    dedup_ratio = overview["deduplication_ratio"]
    if dedup_ratio >= 2.0:
        dedup_points = 15
    elif dedup_ratio >= 1.5:
        dedup_points = 12
    elif dedup_ratio >= 1.2:
        dedup_points = 9
    elif dedup_ratio >= 1.0:
        dedup_points = 5
    else:
        dedup_points = 2

    total_score = rpo_points + job_points + security_points + dedup_points
    total_score = max(0, min(100, total_score))

    status = (
        "EXCELLENT" if total_score >= 85
        else ("HEALTHY" if total_score >= 70
              else ("NEEDS_ATTENTION" if total_score >= 50 else "CRITICAL"))
    )

    if not recs:
        recs.append("Backup system is in peak health. All protection dimensions are optimal.")

    return {
        "status": status,
        "rating": status,
        "score": total_score,
        "health_score": total_score,
        "recommendations": recs,
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


def get_backup_failure_trends(user_id: str, db: Session, lookback_days: int = 30) -> Dict[str, Any]:
    """
    Analyze historical backup failures, group errors by root cause, and produce actionable remediation advice.
    """
    since_date = datetime.utcnow() - timedelta(days=lookback_days)
    jobs = db.query(BackupJob).filter(
        BackupJob.user_id == user_id,
        BackupJob.started_at >= since_date
    ).order_by(BackupJob.started_at.desc()).all()

    total_jobs = len(jobs)
    successful_jobs = sum(1 for j in jobs if j.status == "SUCCESS")
    failed_jobs = [j for j in jobs if j.status == "FAILED"]
    total_failed = len(failed_jobs)

    success_rate = round((successful_jobs / total_jobs) * 100, 1) if total_jobs > 0 else 100.0
    failure_rate = round((total_failed / total_jobs) * 100, 1) if total_jobs > 0 else 0.0

    # Categorize root causes
    root_cause_counts: Dict[str, int] = {
        "PERMISSION_DENIED": 0,
        "TIMEOUT_OR_NETWORK": 0,
        "INTEGRITY_CHECK_FAILED": 0,
        "STORAGE_QUOTA_EXCEEDED": 0,
        "STORAGE_PROVIDER_ERROR": 0,
        "OTHER_EXCEPTION": 0
    }

    remediation_map = {
        "PERMISSION_DENIED": "Check file system permissions on source directories or grant read rights to CloudVault.",
        "TIMEOUT_OR_NETWORK": "Verify network connectivity and cloud endpoint availability; review timeout settings.",
        "INTEGRITY_CHECK_FAILED": "File modification occurred during backup or upload data was corrupted. Ensure quiet file writes.",
        "STORAGE_QUOTA_EXCEEDED": "Storage quota limit reached. Upgrade quota or prune old snapshots using retention rules.",
        "STORAGE_PROVIDER_ERROR": "Cloud storage driver returned an error. Check cloud credentials and bucket permissions.",
        "OTHER_EXCEPTION": "Inspect the activity log details for full traceback and system details."
    }

    recent_failure_list = []
    for j in failed_jobs:
        err = (j.error_message or "").lower()
        if any(w in err for w in ["permission", "access denied", "errno 13", "forbidden", "eacces"]):
            cause = "PERMISSION_DENIED"
        elif any(w in err for w in ["timeout", "timed out", "unreachable", "network", "socket", "connection"]):
            cause = "TIMEOUT_OR_NETWORK"
        elif any(w in err for w in ["integrity", "sha256", "checksum", "hash mismatch", "corrupt"]):
            cause = "INTEGRITY_CHECK_FAILED"
        elif any(w in err for w in ["quota", "full", "space", "limit reached", "enospc"]):
            cause = "STORAGE_QUOTA_EXCEEDED"
        elif any(w in err for w in ["provider", "bucket", "gcs", "s3", "blob", "storage error"]):
            cause = "STORAGE_PROVIDER_ERROR"
        else:
            cause = "OTHER_EXCEPTION"

        root_cause_counts[cause] += 1
        if len(recent_failure_list) < 10:
            recent_failure_list.append({
                "job_id": j.id,
                "plan_id": j.plan_id,
                "started_at": j.started_at.isoformat() if j.started_at else None,
                "root_cause": cause,
                "error_message": j.error_message or "Unknown execution error",
                "remediation": remediation_map[cause]
            })

    root_cause_analysis = []
    for cause, count in root_cause_counts.items():
        if count > 0:
            pct = round((count / total_failed) * 100, 1) if total_failed > 0 else 0.0
            root_cause_analysis.append({
                "category": cause,
                "count": count,
                "percentage": pct,
                "remediation": remediation_map[cause]
            })

    root_cause_analysis.sort(key=lambda x: x["count"], reverse=True)

    return {
        "status": "success",
        "lookback_days": lookback_days,
        "total_jobs": total_jobs,
        "successful_jobs": successful_jobs,
        "failed_jobs": total_failed,
        "success_rate_percentage": success_rate,
        "failure_rate_percentage": failure_rate,
        "root_cause_counts": root_cause_counts,
        "root_cause_analysis": root_cause_analysis,
        "recent_failures": recent_failure_list
    }


def get_storage_optimization_suggestions(user_id: str, db: Session) -> Dict[str, Any]:
    """
    Produce intelligent storage optimization and retention recommendations:
    - Inactive backup plans
    - Heavy storage consumers
    - Cold data tiering opportunities
    - Deduplication multipliers
    """
    plans = db.query(BackupPlan).filter(BackupPlan.user_id == user_id, BackupPlan.is_active == True).all()
    overview = get_analytics_overview(user_id, db)
    suggestions = []

    # 1. Stale / Inactive Plans Check
    for p in plans:
        latest = db.query(Snapshot).filter(Snapshot.plan_id == p.id).order_by(Snapshot.created_at.desc()).first()
        if not latest:
            suggestions.append({
                "type": "STALE_PLAN",
                "severity": "MEDIUM",
                "title": f"Plan '{p.plan_name}' has never executed",
                "recommendation": "Execute an initial backup or schedule automatic runs to start protecting files."
            })
        elif (datetime.utcnow() - latest.created_at).total_seconds() > 14 * 86400:
            days_ago = int((datetime.utcnow() - latest.created_at).total_seconds() / 86400)
            suggestions.append({
                "type": "STALE_PLAN",
                "severity": "HIGH",
                "title": f"Plan '{p.plan_name}' inactive for {days_ago} days",
                "recommendation": "Execute an immediate backup to refresh snapshot protection."
            })

    # 2. Cold Data Archival Suggestion
    cold_summary = overview.get("cold_data_summary", {})
    if cold_summary.get("cold_files_count", 0) > 0 and cold_summary.get("potential_archive_savings_usd", 0) > 0.05:
        suggestions.append({
            "type": "COLD_DATA_TIERING",
            "severity": "LOW",
            "title": "Cold Data Lifecycle Opportunity",
            "recommendation": cold_summary["tiering_recommendation"]
        })

    # 3. Deduplication Efficiency Recognition
    dedup_ratio = overview["deduplication_ratio"]
    if dedup_ratio >= 1.5:
        suggestions.append({
            "type": "DEDUP_EFFICIENCY",
            "severity": "INFO",
            "title": f"Strong Content Deduplication ({dedup_ratio}x)",
            "recommendation": f"CloudVault deduplication has avoided uploading {round(overview['bytes_saved'] / (1024*1024), 1)} MB of redundant data."
        })
    elif dedup_ratio < 1.1 and overview["logical_uncompressed_bytes"] > 50 * 1024 * 1024:
        suggestions.append({
            "type": "DEDUP_EFFICIENCY",
            "severity": "LOW",
            "title": "Unique Content Profile",
            "recommendation": "Most protected files are distinct or pre-compressed (e.g. video/archives). Incremental deduplication continues to protect unmodified blocks."
        })

    # 4. Backup Cadence Recommendation
    total_files = db.query(func.count(SnapshotFile.id)).join(Snapshot).filter(
        Snapshot.user_id == user_id,
        SnapshotFile.is_deleted == False
    ).scalar() or 0

    cadence = "Daily" if total_files > 50 else "Continuous / Hourly" if total_files > 500 else "Daily or Weekly"
    suggestions.append({
        "type": "CADENCE_RECOMMENDATION",
        "severity": "INFO",
        "title": f"Recommended Cadence: {cadence}",
        "recommendation": f"Based on your protected inventory of {total_files} active files, a {cadence.lower()} backup schedule balances RPO recency and cloud network overhead."
    })

    return {
        "status": "success",
        "total_suggestions": len(suggestions),
        "suggestions": suggestions,
        "cold_data_summary": cold_summary
    }
