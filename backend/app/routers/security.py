import json
import os
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models import User, BackupPlan, Snapshot, RansomwareAlert, AuditLog
from backend.app.auth import get_current_user
from backend.app.config import settings
from backend.app.services.ransomware_service import (
    analyze_file_activity,
    analyze_file_list,
    scan_and_evaluate_plan,
    resolve_security_alert,
    simulate_ransomware_scenario,
    calculate_shannon_entropy
)
from backend.app.ai.security import record_audit_log

router = APIRouter(prefix="/api/v1/security", tags=["Security & Anomaly Defense"])

class AnalyzePathRequest(BaseModel):
    plan_id: Optional[str] = None
    target_directory: Optional[str] = None

class DismissAlertRequest(BaseModel):
    resolution_notes: Optional[str] = "False positive verified by user"

class ResolveAlertRequest(BaseModel):
    resolution_notes: Optional[str] = "Threat resolved and verified safe"
    unquarantine_snapshots: Optional[bool] = True

class SimulateAttackRequest(BaseModel):
    scenario_type: Optional[str] = "mass_encryption"  # 'mass_encryption', 'suspicious_extension', 'high_entropy_archive'

@router.get("/alerts")
def list_security_alerts(
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve all active or historical ransomware alerts for the authenticated user."""
    query = db.query(RansomwareAlert).filter(RansomwareAlert.user_id == current_user.id)
    if status and status.upper() != "ALL":
        query = query.filter(RansomwareAlert.status == status.upper())

    alerts = query.order_by(RansomwareAlert.created_at.desc()).all()
    results = []
    for a in alerts:
        try:
            exts = json.loads(a.matched_extensions)
        except Exception:
            exts = []
        try:
            reasons = json.loads(a.details)
        except Exception:
            reasons = [a.details]

        results.append({
            "alert_id": a.id,
            "plan_id": a.plan_id,
            "risk_score": a.risk_score,
            "alert_level": a.alert_level,
            "suspicious_files_count": a.suspicious_files_count,
            "average_entropy": a.average_entropy,
            "matched_extensions": exts,
            "reasons": reasons,
            "status": a.status,
            "created_at": a.created_at.isoformat()
        })
    return {"alerts": results, "total": len(results)}

@router.get("/health")
def get_security_health(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get real-time security defense posture, risk meters, and ransomware monitoring metrics."""
    active_alerts = db.query(RansomwareAlert).filter(
        RansomwareAlert.user_id == current_user.id,
        RansomwareAlert.status == "ACTIVE"
    ).all()

    quarantined_count = sum(1 for a in active_alerts if a.alert_level == "QUARANTINED")
    max_risk = max((a.risk_score for a in active_alerts), default=0)

    total_plans = db.query(BackupPlan).filter(
        BackupPlan.user_id == current_user.id,
        BackupPlan.is_active == True
    ).count()

    shielded_snapshots = db.query(Snapshot).filter(
        Snapshot.user_id == current_user.id,
        Snapshot.is_locked == True
    ).count()

    recent_critical_audits = db.query(AuditLog).filter(
        AuditLog.user_id == current_user.id,
        AuditLog.severity.in_(["WARNING", "CRITICAL"])
    ).count()

    if quarantined_count > 0 or max_risk >= 80:
        overall_status = "CRITICAL"
    elif len(active_alerts) > 0 or max_risk >= 30:
        overall_status = "WARNING"
    else:
        overall_status = "HEALTHY"

    return {
        "status": overall_status,
        "overall_risk_score": max_risk,
        "shield_active": True,
        "active_ransomware_alerts": len(active_alerts),
        "quarantined_alerts_count": quarantined_count,
        "shielded_snapshots_count": shielded_snapshots,
        "monitored_backup_plans": total_plans,
        "recent_security_events": recent_critical_audits,
        "thresholds": {
            "entropy_threshold": getattr(settings, "RANSOMWARE_ENTROPY_THRESHOLD", 7.50),
            "suspicious_threshold": getattr(settings, "RISK_THRESHOLD_SUSPICIOUS", 30),
            "high_risk_threshold": getattr(settings, "RISK_THRESHOLD_HIGH", 60),
            "critical_threshold": getattr(settings, "RISK_THRESHOLD_CRITICAL", 80)
        },
        "heuristics": {
            "entropy_detection": "Shannon Entropy Delta & Absolute (H >= 7.50 bits/byte)",
            "monitored_extensions_count": 21,
            "worm_auto_lock": "Active on Risk >= 60"
        }
    }

@router.post("/analyze-path")
def analyze_path_for_ransomware(
    req: AnalyzePathRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """On-demand scan of a local directory or configured plan for ransomware patterns."""
    if req.plan_id:
        plan = db.query(BackupPlan).filter(BackupPlan.id == req.plan_id, BackupPlan.user_id == current_user.id).first()
        if not plan:
            raise HTTPException(status_code=404, detail="Backup plan not found.")
        alert = scan_and_evaluate_plan(plan.id, current_user.id, db)
        return {
            "status": "COMPLETED",
            "plan_id": plan.id,
            "alert_generated": alert is not None,
            "alert_id": alert.id if alert else None,
            "risk_score": alert.risk_score if alert else 0,
            "alert_level": alert.alert_level if alert else "NORMAL"
        }

    target_dir = req.target_directory
    if not target_dir or not os.path.exists(target_dir):
        raise HTTPException(status_code=400, detail="Target directory does not exist.")

    files = []
    for root, _, fs in os.walk(target_dir):
        for f in fs:
            p = os.path.join(root, f)
            files.append({
                "full_path": p,
                "file_name": f,
                "file_extension": os.path.splitext(f)[1].lower()
            })
            if len(files) >= 250:
                break

    analysis = analyze_file_activity(files)
    return {
        "status": "COMPLETED",
        "scanned_files_count": len(files),
        "analysis": analysis
    }

@router.post("/alerts/{alert_id}/dismiss")
def dismiss_security_alert(
    alert_id: str,
    req: DismissAlertRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Acknowledge and dismiss an active ransomware alert."""
    alert = db.query(RansomwareAlert).filter(
        RansomwareAlert.id == alert_id,
        RansomwareAlert.user_id == current_user.id
    ).first()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    alert.status = "DISMISSED"
    db.commit()

    record_audit_log(
        user_id=current_user.id,
        event_type="RANSOMWARE_ALERT_DISMISSED",
        action=f"Dismissed alert {alert.id}",
        details={"alert_id": alert.id, "notes": req.resolution_notes},
        db=db,
        severity="INFO"
    )

    return {"status": "SUCCESS", "message": "Alert marked as dismissed.", "alert_id": alert.id}

@router.post("/alerts/{alert_id}/resolve")
def resolve_alert(
    alert_id: str,
    req: ResolveAlertRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Resolve an active alert and reversibly unquarantine affected snapshots."""
    try:
        res = resolve_security_alert(
            alert_id=alert_id,
            user_id=current_user.id,
            resolution_notes=req.resolution_notes or "Resolved by user",
            unquarantine_snapshots=bool(req.unquarantine_snapshots),
            db=db
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/simulate-test")
def simulate_attack_test(
    req: SimulateAttackRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Execute a 100% safe, non-destructive ransomware simulation in a temporary isolated sandbox.
    Never touches user files or database backups.
    """
    res = simulate_ransomware_scenario(
        user_id=current_user.id,
        db=db,
        scenario_type=req.scenario_type or "mass_encryption"
    )
    return res

@router.get("/audit-logs")
def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve immutable, hash-chained security and system audit logs."""
    logs = db.query(AuditLog).filter(
        AuditLog.user_id == current_user.id
    ).order_by(AuditLog.created_at.desc()).limit(limit).all()

    results = []
    for l in logs:
        try:
            details = json.loads(l.details)
        except Exception:
            details = {"raw": l.details}

        results.append({
            "id": l.id,
            "event_type": l.event_type,
            "severity": l.severity,
            "action": l.action,
            "details": details,
            "prev_hash": l.prev_hash,
            "current_hash": l.current_hash,
            "created_at": l.created_at.isoformat()
        })
    return {"audit_logs": results, "count": len(results)}
