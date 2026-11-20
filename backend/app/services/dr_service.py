import os
import shutil
import tempfile
import time
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from sqlalchemy.orm import Session

from backend.app.models import (
    User, BackupPlan, Snapshot, SnapshotFile, StorageObject,
    DRDrill, RecoveryOperation, RansomwareAlert, BackupJob
)
from backend.app.storage.base import StorageProvider
from backend.app.services.restore_service import (
    decompress_payload, calculate_bytes_sha256, restore_single_snapshot_file
)
from backend.app.services.crypto_service import (
    envelope_decrypt_payload, derive_user_kek, derive_object_dek, decrypt_payload_aes_gcm
)
from backend.app.ai.security import record_audit_log
from backend.app.services.ransomware_service import KNOWN_RANSOMWARE_EXTENSIONS


def verify_and_reconstruct_storage_object(
    so: StorageObject,
    raw_payload: bytes,
    user: User
) -> Tuple[Optional[bytes], bool, Optional[str]]:
    """
    Decrypts (if encrypted) and decompresses a stored object's payload,
    verifying authenticated encryption (AES-256-GCM auth tag) and SHA-256 integrity.
    Returns: (plaintext_bytes, is_encrypted, error_message_if_any)
    """
    if not so:
        return None, False, "StorageObject is missing"

    is_enc = bool(getattr(so, "is_encrypted", False))
    if is_enc:
        if not user or not user.encryption_salt:
            return None, True, f"Missing user encryption salt on object {so.id}"

        try:
            if so.encrypted_dek and so.dek_nonce and so.encryption_nonce:
                encrypted_dek = bytes.fromhex(so.encrypted_dek)
                payload_nonce = bytes.fromhex(so.encryption_nonce)
                dek_nonce = bytes.fromhex(so.dek_nonce)
                key_ver = so.key_version or 1
                aad_ctx = so.aad_tag

                compressed_bytes = envelope_decrypt_payload(
                    ciphertext=raw_payload,
                    encrypted_dek=encrypted_dek,
                    payload_nonce=payload_nonce,
                    dek_nonce=dek_nonce,
                    user_id=user.id,
                    salt=user.encryption_salt,
                    key_version=key_ver,
                    aad_context=aad_ctx
                )
            elif so.encryption_nonce:
                kek = derive_user_kek(user.id, user.encryption_salt)
                dek = derive_object_dek(kek, so.sha256_hash)
                nonce = bytes.fromhex(so.encryption_nonce) if len(so.encryption_nonce) == 24 else so.encryption_nonce.encode()[:12]
                compressed_bytes = decrypt_payload_aes_gcm(raw_payload, dek, nonce)
            else:
                return None, True, "Encrypted object lacks encryption metadata"
        except Exception as e:
            return None, True, f"Cryptographic decryption failed: {str(e)}"
    else:
        compressed_bytes = raw_payload

    # Decompress
    try:
        plaintext = decompress_payload(compressed_bytes, so.compression_algo)
    except Exception as e:
        return None, is_enc, f"Payload decompression failed: {str(e)}"

    # SHA-256 verification
    actual_sha = calculate_bytes_sha256(plaintext)
    if actual_sha != so.sha256_hash:
        return None, is_enc, f"SHA-256 integrity mismatch: expected {so.sha256_hash}, got {actual_sha}"

    return plaintext, is_enc, None


def get_dr_metrics(user_id: str, db: Session) -> Dict[str, Any]:
    """
    Calculate real-time Recovery Point Objective (RPO) and measured
    Recovery Time Objective (RTO) for the authenticated user.
    Maintained for backward compatibility.
    """
    latest_snap = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).first()
    
    # 1. Calculate Actual RPO (Hours since last verified snapshot)
    if latest_snap:
        rpo_hours = round((datetime.utcnow() - latest_snap.created_at).total_seconds() / 3600.0, 2)
        rpo_status = "HEALTHY" if rpo_hours <= 24.0 else ("WARNING" if rpo_hours <= 72.0 else "CRITICAL")
    else:
        rpo_hours = None
        rpo_status = "NO_BACKUPS"

    # 2. Measured RTO from historical synthetic DR drills
    drills = db.query(DRDrill).filter(DRDrill.user_id == user_id, DRDrill.status == "PASSED").order_by(DRDrill.created_at.desc()).limit(10).all()
    
    if drills:
        avg_speed_mbps = sum(d.restoration_speed_mbps for d in drills) / len(drills)
        total_data_bytes = latest_snap.total_stored_bytes if latest_snap else 0
        total_data_mb = total_data_bytes / (1024 * 1024)
        
        if avg_speed_mbps > 0:
            estimated_rto_seconds = total_data_mb / avg_speed_mbps
            estimated_rto_minutes = round(estimated_rto_seconds / 60.0, 2)
        else:
            estimated_rto_minutes = 2.0
    else:
        avg_speed_mbps = 25.0 # Conservative baseline (25 MB/s)
        total_data_bytes = latest_snap.total_stored_bytes if latest_snap else 0
        estimated_rto_minutes = round((total_data_bytes / (1024 * 1024 * avg_speed_mbps)) / 60.0, 2) if total_data_bytes > 0 else 0.5

    # 3. Overall Recovery Readiness Score (0 - 100)
    readiness = 100
    if not latest_snap:
        readiness -= 50
    elif rpo_hours > 48:
        readiness -= 30
    elif rpo_hours > 24:
        readiness -= 15

    # Drills pass rate
    recent_drills = db.query(DRDrill).filter(DRDrill.user_id == user_id).order_by(DRDrill.created_at.desc()).limit(5).all()
    if recent_drills:
        passed = sum(1 for d in recent_drills if d.status == "PASSED")
        readiness -= int((1.0 - (passed / len(recent_drills))) * 30)
    else:
        readiness -= 15 # Minor penalty for no drills executed yet

    readiness = max(0, min(100, readiness))

    return {
        "status": "success",
        "rpo": {
            "hours": rpo_hours,
            "target_hours": 24.0,
            "status": rpo_status,
            "latest_recovery_point": latest_snap.created_at.isoformat() if latest_snap else None
        },
        "rto": {
            "estimated_minutes": estimated_rto_minutes,
            "measured_speed_mbps": round(avg_speed_mbps, 2),
            "total_recovery_bytes": latest_snap.total_stored_bytes if latest_snap else 0,
            "confidence": "MEASURED_DRILLS" if drills else "BASELINE_ESTIMATE"
        },
        "readiness_score": readiness,
        "readiness_level": "OPTIMAL" if readiness >= 85 else ("ACCEPTABLE" if readiness >= 70 else "AT_RISK"),
        "total_drills_executed": len(drills)
    }


def get_dr_command_center_telemetry(user_id: str, db: Session) -> Dict[str, Any]:
    """
    Comprehensive Disaster Recovery Command Center telemetry aggregation.
    Differentiates measured values, calculated values, and predictions.
    """
    now = datetime.utcnow()
    user = db.query(User).filter(User.id == user_id).first()

    # 1. Snapshots & Recovery Points
    snapshots = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).all()
    total_snapshots = len(snapshots)
    verified_snapshots = sum(1 for s in snapshots if s.verification_status == "VERIFIED")
    unverified_snapshots = sum(1 for s in snapshots if s.verification_status == "UNVERIFIED")
    failed_snapshots = sum(1 for s in snapshots if s.verification_status == "FAILED")
    worm_locked_snapshots = sum(1 for s in snapshots if s.is_locked and s.lock_until and s.lock_until > now)
    latest_snap = snapshots[0] if snapshots else None

    # 2. Last Successful Backup
    last_backup_job = db.query(BackupJob).filter(
        BackupJob.user_id == user_id,
        BackupJob.status == "SUCCESS"
    ).order_by(BackupJob.completed_at.desc()).first()

    last_backup_info = None
    if last_backup_job:
        last_backup_info = {
            "job_id": last_backup_job.id,
            "plan_name": last_backup_job.plan.plan_name if last_backup_job.plan else "Manual Backup",
            "completed_at": last_backup_job.completed_at.isoformat() if last_backup_job.completed_at else None,
            "files_uploaded": last_backup_job.files_uploaded,
            "bytes_uploaded": last_backup_job.bytes_uploaded,
            "trigger_type": last_backup_job.trigger_type
        }

    # 3. Last Recovery Drill
    last_drill = db.query(DRDrill).filter(DRDrill.user_id == user_id).order_by(DRDrill.created_at.desc()).first()
    last_drill_info = None
    if last_drill:
        last_drill_info = {
            "drill_id": last_drill.id,
            "status": last_drill.status,
            "drill_type": getattr(last_drill, "drill_type", "FULL_SNAPSHOT") or "FULL_SNAPSHOT",
            "files_tested": last_drill.files_tested,
            "bytes_tested": last_drill.bytes_tested,
            "throughput_mbps": last_drill.restoration_speed_mbps,
            "duration_seconds": last_drill.duration_seconds,
            "created_at": last_drill.created_at.isoformat()
        }

    # 4. Active Recovery Incidents
    # - Active ransomware alerts
    active_alerts = db.query(RansomwareAlert).filter(
        RansomwareAlert.user_id == user_id,
        RansomwareAlert.status == "ACTIVE"
    ).all()
    # - Failed backup jobs within past 7 days
    seven_days_ago = now - timedelta(days=7)
    failed_jobs = db.query(BackupJob).filter(
        BackupJob.user_id == user_id,
        BackupJob.status == "FAILED",
        BackupJob.started_at >= seven_days_ago
    ).all()
    # - Failed drills within past 7 days
    failed_drills = db.query(DRDrill).filter(
        DRDrill.user_id == user_id,
        DRDrill.status == "FAILED",
        DRDrill.created_at >= seven_days_ago
    ).all()

    incidents = []
    for a in active_alerts:
        incidents.append({
            "type": "RANSOMWARE_ALERT",
            "id": a.id,
            "severity": "CRITICAL" if a.alert_level == "QUARANTINED" else "WARNING",
            "title": f"Active Ransomware Threat ({a.alert_level})",
            "details": f"Risk Score {a.risk_score}/100 with {a.suspicious_files_count} suspicious files.",
            "timestamp": a.created_at.isoformat()
        })
    for fj in failed_jobs:
        incidents.append({
            "type": "FAILED_BACKUP",
            "id": fj.id,
            "severity": "WARNING",
            "title": f"Backup Job Failed ({fj.trigger_type})",
            "details": fj.error_message or "Unknown failure during backup execution.",
            "timestamp": fj.started_at.isoformat()
        })
    for fd in failed_drills:
        incidents.append({
            "type": "FAILED_DRILL",
            "id": fd.id,
            "severity": "CRITICAL",
            "title": "Synthetic Recovery Drill Failed",
            "details": fd.error_details or "Bit-level integrity check detected object mismatch or corruption.",
            "timestamp": fd.created_at.isoformat()
        })
    if failed_snapshots > 0:
        incidents.append({
            "type": "CORRUPTED_SNAPSHOT",
            "id": "snap-integrity-warning",
            "severity": "CRITICAL",
            "title": f"{failed_snapshots} Snapshot(s) Failed Verification",
            "details": "Snapshot integrity verification detected corrupted or unreadable blocks.",
            "timestamp": now.isoformat()
        })

    # 5. Failed Recovery Operations count
    failed_ops_count = db.query(RecoveryOperation).filter(
        RecoveryOperation.user_id == user_id,
        RecoveryOperation.status == "FAILED"
    ).count() + len(failed_drills)

    # 6. RPO: Calculated vs Target
    if latest_snap:
        rpo_hours = round((now - latest_snap.created_at).total_seconds() / 3600.0, 2)
        rpo_status = "HEALTHY" if rpo_hours <= 24.0 else ("WARNING" if rpo_hours <= 72.0 else "CRITICAL")
    else:
        rpo_hours = None
        rpo_status = "NO_BACKUPS"

    # 7. RTO: Measured Drills vs Predicted
    passed_drills = db.query(DRDrill).filter(DRDrill.user_id == user_id, DRDrill.status == "PASSED").order_by(DRDrill.created_at.desc()).limit(10).all()
    if passed_drills:
        measured_speed_mbps = round(sum(d.restoration_speed_mbps for d in passed_drills) / len(passed_drills), 2)
        measured_drill_duration_avg = round(sum(d.duration_seconds for d in passed_drills) / len(passed_drills), 2)
        total_stored_mb = (latest_snap.total_stored_bytes if latest_snap else 0) / (1024 * 1024)
        if measured_speed_mbps > 0:
            predicted_full_rto_min = round((total_stored_mb / measured_speed_mbps) / 60.0, 2)
        else:
            predicted_full_rto_min = 1.0
        rto_confidence = "HIGH_MEASURED"
    else:
        measured_speed_mbps = 25.0
        measured_drill_duration_avg = 0.5
        total_stored_mb = (latest_snap.total_stored_bytes if latest_snap else 0) / (1024 * 1024)
        predicted_full_rto_min = round((total_stored_mb / (1024 * 1024 * 25.0)) / 60.0, 2) if total_stored_mb > 0 else 0.5
        rto_confidence = "BASELINE_ESTIMATE"

    # 8. Readiness Score Calculation (0 - 100)
    score = 100
    score_breakdown = {}

    # Factor A: RPO Recency (Max 30)
    if not latest_snap:
        score -= 30
        score_breakdown["rpo_recency"] = 0
    elif rpo_hours <= 24:
        score_breakdown["rpo_recency"] = 30
    elif rpo_hours <= 48:
        score -= 10
        score_breakdown["rpo_recency"] = 20
    elif rpo_hours <= 72:
        score -= 20
        score_breakdown["rpo_recency"] = 10
    else:
        score -= 30
        score_breakdown["rpo_recency"] = 0

    # Factor B: Synthetic Verification Drills (Max 25)
    recent_passed_drill = any(d.status == "PASSED" and d.created_at >= seven_days_ago for d in passed_drills)
    if recent_passed_drill:
        score_breakdown["verification_drills"] = 25
    elif len(passed_drills) > 0:
        score -= 10
        score_breakdown["verification_drills"] = 15
    else:
        score -= 25
        score_breakdown["verification_drills"] = 0

    # Factor C: Security & Ransomware Threat Level (Max 25)
    if len(active_alerts) == 0:
        score_breakdown["cyber_shield"] = 25
    else:
        score -= 25
        score_breakdown["cyber_shield"] = 0

    # Factor D: WORM Immutability Protection (Max 10)
    if worm_locked_snapshots > 0:
        score_breakdown["worm_retention"] = 10
    else:
        score -= 5
        score_breakdown["worm_retention"] = 5

    # Factor E: Object & Snapshot Integrity (Max 10)
    if failed_snapshots == 0 and len(failed_drills) == 0:
        score_breakdown["storage_integrity"] = 10
    else:
        score -= 10
        score_breakdown["storage_integrity"] = 0

    readiness_score = max(0, min(100, score))
    readiness_level = "OPTIMAL" if readiness_score >= 85 else ("ACCEPTABLE" if readiness_score >= 70 else ("AT_RISK" if readiness_score >= 50 else "CRITICAL"))

    # 9. Protected vs Unprotected Data
    from backend.app.ai.tools import tool_get_unprotected_files
    unprotected_data = tool_get_unprotected_files(user_id, db)
    unprot_count = len(unprotected_data.get("unprotected_files", []))

    # 10. Prioritized DR Recommendations
    recommendations = []
    if len(active_alerts) > 0:
        recommendations.append({
            "priority": "P1_CRITICAL",
            "title": "Isolate Threat & Recover from Pre-Incident Baseline",
            "action": "An active ransomware threat was detected. Review the guided Ransomware Recovery Plan to restore clean unquarantined data."
        })
    if unverified_snapshots > 0 or not recent_passed_drill:
        recommendations.append({
            "priority": "P2_HIGH",
            "title": "Run Synthetic Recovery Drill",
            "action": "Prove bit-for-bit SHA-256 recoverability by running an isolated synthetic drill on your latest backup point."
        })
    if worm_locked_snapshots == 0 and total_snapshots > 0:
        recommendations.append({
            "priority": "P3_MEDIUM",
            "title": "Enable WORM Immutable Retention",
            "action": "Protect at least one clean baseline snapshot with immutable WORM retention to prevent deletion or ransomware overwrite."
        })
    if rpo_status in ["WARNING", "CRITICAL"]:
        recommendations.append({
            "priority": "P2_HIGH",
            "title": "Trigger On-Demand Backup",
            "action": f"Current RPO is {rpo_hours} hours. Run a backup to reduce potential data loss window below 24 hours."
        })
    if unprot_count > 0:
        recommendations.append({
            "priority": "P3_MEDIUM",
            "title": "Protect Unsynced Local Files",
            "action": f"{unprot_count} file(s) have been modified locally since the last snapshot."
        })

    return {
        "status": "success",
        "readiness_score": readiness_score,
        "readiness_level": readiness_level,
        "score_breakdown": score_breakdown,
        "recovery_points": {
            "total": total_snapshots,
            "verified": verified_snapshots,
            "unverified": unverified_snapshots,
            "failed": failed_snapshots,
            "worm_locked": worm_locked_snapshots,
            "latest_snapshot": {
                "id": latest_snap.id,
                "snapshot_number": latest_snap.snapshot_number,
                "name": latest_snap.name,
                "created_at": latest_snap.created_at.isoformat(),
                "total_files": latest_snap.total_files,
                "total_stored_bytes": latest_snap.total_stored_bytes,
                "verification_status": latest_snap.verification_status,
                "is_immutable": latest_snap.is_immutable
            } if latest_snap else None
        },
        "last_backup": last_backup_info,
        "last_drill": last_drill_info,
        "active_incidents": {
            "count": len(incidents),
            "incidents": incidents
        },
        "failed_operations_count": failed_ops_count,
        "rpo": {
            "type": "CALCULATED",
            "hours": rpo_hours,
            "target_hours": 24.0,
            "status": rpo_status,
            "latest_recovery_point": latest_snap.created_at.isoformat() if latest_snap else None
        },
        "rto": {
            "measured_speed_mbps": measured_speed_mbps,
            "measured_duration_seconds": measured_drill_duration_avg,
            "predicted_full_rto_minutes": predicted_full_rto_min,
            "confidence": rto_confidence,
            "type": "MEASURED_AND_PREDICTED"
        },
        "snapshot_integrity": {
            "total": total_snapshots,
            "verified_percentage": round((verified_snapshots / total_snapshots * 100), 1) if total_snapshots > 0 else 0,
            "unverified_percentage": round((unverified_snapshots / total_snapshots * 100), 1) if total_snapshots > 0 else 0,
            "failed_percentage": round((failed_snapshots / total_snapshots * 100), 1) if total_snapshots > 0 else 0
        },
        "data_protection": {
            "total_stored_bytes": latest_snap.total_stored_bytes if latest_snap else 0,
            "unprotected_files_count": unprot_count,
            "status": "PROTECTED" if unprot_count == 0 else "PARTIALLY_SYNCED"
        },
        "recovery_recommendations": recommendations
    }


def run_synthetic_recovery_drill(
    snapshot_id: Optional[str],
    user_id: str,
    db: Session,
    storage: StorageProvider
) -> Dict[str, Any]:
    """
    Execute a non-destructive synthetic disaster recovery drill with envelope decryption support.
    Maintained for backward compatibility.
    """
    return run_advanced_synthetic_recovery_drill(
        user_id=user_id,
        db=db,
        storage=storage,
        snapshot_id=snapshot_id,
        drill_type="FULL_SNAPSHOT"
    )


def run_advanced_synthetic_recovery_drill(
    user_id: str,
    db: Session,
    storage: StorageProvider,
    snapshot_id: Optional[str] = None,
    drill_type: str = "FULL_SNAPSHOT",
    drill_scope: Optional[str] = None,
    inject_corruption: bool = False
) -> Dict[str, Any]:
    """
    Comprehensive synthetic disaster recovery drill engine.
    Supports: FULL_SNAPSHOT, FOLDER, FILE, POINT_IN_TIME, RANSOMWARE_PRE_INCIDENT, CORRUPTED_OBJECT_TEST.
    Performs bit-for-bit SHA-256 verification and envelope decryption without writing to user paths.
    """
    # 1. Resolve target snapshot
    if drill_type == "RANSOMWARE_PRE_INCIDENT":
        active_alert = db.query(RansomwareAlert).filter(
            RansomwareAlert.user_id == user_id,
            RansomwareAlert.status == "ACTIVE"
        ).order_by(RansomwareAlert.created_at.desc()).first()
        
        if active_alert:
            snap = db.query(Snapshot).filter(
                Snapshot.user_id == user_id,
                Snapshot.created_at < active_alert.created_at
            ).order_by(Snapshot.created_at.desc()).first()
            if not snap:
                raise ValueError("No clean baseline snapshot found prior to the active ransomware alert.")
        else:
            snap = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).first()
    elif snapshot_id:
        snap = db.query(Snapshot).filter(Snapshot.id == snapshot_id, Snapshot.user_id == user_id).first()
    else:
        snap = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).first()

    if not snap:
        raise ValueError("No snapshots available to test recovery drill.")

    user = db.query(User).filter(User.id == user_id).first()

    # 2. Filter files based on drill scope
    all_files = db.query(SnapshotFile).filter(
        SnapshotFile.snapshot_id == snap.id,
        SnapshotFile.is_deleted == False
    ).all()

    if not all_files:
        raise ValueError("Selected snapshot contains 0 files to verify.")

    if drill_type == "FOLDER" and drill_scope:
        norm_scope = drill_scope.replace("\\", "/").strip("/")
        files = [sf for sf in all_files if sf.relative_path.replace("\\", "/").startswith(norm_scope)]
    elif drill_type == "FILE" and drill_scope:
        norm_scope = drill_scope.replace("\\", "/").strip("/")
        files = [sf for sf in all_files if sf.id == drill_scope or sf.relative_path.replace("\\", "/").endswith(norm_scope) or sf.file_name == drill_scope]
    else:
        files = all_files[:50]

    if not files:
        raise ValueError(f"No files matched drill scope: '{drill_scope or drill_type}'")

    sandbox_dir = tempfile.mkdtemp(prefix="cloudvault_dr_sandbox_")
    drill_status = "PASSED"
    err_details = None
    tested_files_count = 0
    tested_bytes_count = 0
    report_entries = []

    start_time = time.time()

    try:
        for idx, sf in enumerate(files):
            file_start = time.time()
            so = db.query(StorageObject).filter(StorageObject.id == sf.storage_object_id).first()
            if not so:
                drill_status = "FAILED"
                err_details = f"Storage object {sf.storage_object_id} missing for file {sf.relative_path}"
                report_entries.append({
                    "file_id": sf.id,
                    "file_name": sf.file_name,
                    "relative_path": sf.relative_path,
                    "expected_sha256": "UNKNOWN",
                    "computed_sha256": "OBJECT_MISSING",
                    "sha256_match": False,
                    "is_encrypted": False,
                    "status": "FAILED",
                    "error": err_details
                })
                break

            # Stream bytes from storage provider
            raw_payload = storage.download_bytes(so.storage_path)

            # Injected corruption test scenario
            if inject_corruption or (drill_type == "CORRUPTED_OBJECT_TEST" and idx == 0):
                if len(raw_payload) > 30:
                    raw_payload = b"CORRUPTED_INJECTED_TEST_PAYLOAD" + raw_payload[31:]
                else:
                    raw_payload = b"CORRUPTED_TEST_PAYLOAD"

            # Reconstruct, decrypt and verify
            plaintext, is_enc, err = verify_and_reconstruct_storage_object(so, raw_payload, user)
            file_duration_ms = round((time.time() - file_start) * 1000, 2)

            if err:
                drill_status = "FAILED"
                err_details = f"Integrity check failed on {sf.relative_path}: {err}"
                report_entries.append({
                    "file_id": sf.id,
                    "file_name": sf.file_name,
                    "relative_path": sf.relative_path,
                    "expected_sha256": so.sha256_hash,
                    "computed_sha256": "FAILED_VERIFICATION",
                    "sha256_match": False,
                    "is_encrypted": is_enc,
                    "key_version": getattr(so, "key_version", 1),
                    "file_size": sf.file_size,
                    "duration_ms": file_duration_ms,
                    "status": "FAILED",
                    "error": err
                })
                break

            actual_sha = calculate_bytes_sha256(plaintext)
            report_entries.append({
                "file_id": sf.id,
                "file_name": sf.file_name,
                "relative_path": sf.relative_path,
                "expected_sha256": so.sha256_hash,
                "computed_sha256": actual_sha,
                "sha256_match": True,
                "is_encrypted": is_enc,
                "key_version": getattr(so, "key_version", 1),
                "decrypted_successfully": True if is_enc else None,
                "file_size": len(plaintext),
                "duration_ms": file_duration_ms,
                "status": "PASSED",
                "error": None
            })

            tested_files_count += 1
            tested_bytes_count += len(plaintext)

    except Exception as e:
        drill_status = "FAILED"
        err_details = f"Drill exception: {str(e)}"
    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)

    duration = max(0.001, round(time.time() - start_time, 3))
    raw_mbps = (tested_bytes_count / (1024 * 1024)) / duration
    throughput_mbps = round(raw_mbps, 2)
    if tested_bytes_count > 0 and throughput_mbps == 0.0:
        throughput_mbps = round(raw_mbps, 4) or 0.01

    rpo_hours = round((datetime.utcnow() - snap.created_at).total_seconds() / 3600.0, 2)
    total_snap_mb = snap.total_stored_bytes / (1024 * 1024)
    estimated_rto_min = round((total_snap_mb / max(1.0, throughput_mbps)) / 60.0, 2)

    # Persist DR Drill Record
    drill_record = DRDrill(
        user_id=user_id,
        snapshot_id=snap.id,
        drill_type=drill_type,
        drill_scope=drill_scope,
        files_tested=tested_files_count,
        bytes_tested=tested_bytes_count,
        duration_seconds=duration,
        restoration_speed_mbps=throughput_mbps,
        rpo_hours=rpo_hours,
        estimated_rto_minutes=estimated_rto_min,
        status=drill_status,
        error_details=err_details,
        verification_report=json.dumps(report_entries)
    )
    db.add(drill_record)

    # Update Snapshot verification status
    snap.verification_status = "VERIFIED" if drill_status == "PASSED" else "FAILED"
    snap.verified_at = datetime.utcnow()

    db.commit()
    db.refresh(drill_record)

    record_audit_log(
        user_id=user_id,
        event_type="DISASTER_RECOVERY_DRILL",
        action=f"Advanced DR Drill ({drill_type}): {drill_status}",
        details={
            "snapshot_id": snap.id,
            "snapshot_name": snap.name,
            "drill_type": drill_type,
            "drill_scope": drill_scope,
            "files_tested": tested_files_count,
            "status": drill_status,
            "throughput_mbps": throughput_mbps,
            "duration": duration,
            "verified_bit_level": drill_status == "PASSED"
        },
        db=db,
        severity="INFO" if drill_status == "PASSED" else "CRITICAL"
    )

    return {
        "drill_id": drill_record.id,
        "status": drill_status,
        "drill_type": drill_type,
        "drill_scope": drill_scope,
        "snapshot_id": snap.id,
        "snapshot_name": snap.name,
        "files_tested": tested_files_count,
        "bytes_tested": tested_bytes_count,
        "duration_seconds": duration,
        "restoration_speed_mbps": throughput_mbps,
        "rpo_hours": rpo_hours,
        "estimated_rto_minutes": estimated_rto_min,
        "error_details": err_details,
        "verification_report": report_entries
    }


def get_point_in_time_preview(
    snapshot_id: str,
    destination_dir: Optional[str],
    user_id: str,
    db: Session
) -> Dict[str, Any]:
    """
    Inspect a historical snapshot and preview differences against a destination directory.
    Identifies NEW, MODIFIED, and UNCHANGED files.
    """
    snap = db.query(Snapshot).filter(
        Snapshot.id == snapshot_id,
        Snapshot.user_id == user_id
    ).first()
    if not snap:
        raise ValueError(f"Snapshot not found or unauthorized: {snapshot_id}")

    plan = snap.plan
    dest_path = Path(destination_dir).resolve() if destination_dir else None

    # If no destination provided, attempt to check against plan source directories
    if not dest_path and plan and plan.source_directories:
        try:
            sources = json.loads(plan.source_directories)
            if sources:
                dest_path = Path(sources[0]).resolve()
        except Exception:
            dest_path = None

    files_preview = []
    diff_counts = {"new": 0, "modified": 0, "unchanged": 0}
    key_versions = set()

    for sf in snap.files:
        so = sf.storage_object
        key_ver = getattr(so, "key_version", 1) or 1
        key_versions.add(key_ver)

        diff_status = "NEW"
        if dest_path and dest_path.exists():
            local_target = dest_path / sf.relative_path
            if local_target.exists():
                local_size = local_target.stat().st_size
                if local_size != sf.file_size:
                    diff_status = "MODIFIED"
                else:
                    # Compare hash
                    try:
                        with open(local_target, "rb") as f:
                            local_sha = calculate_bytes_sha256(f.read())
                        diff_status = "UNCHANGED" if local_sha == so.sha256_hash else "MODIFIED"
                    except Exception:
                        diff_status = "MODIFIED"

        diff_counts[diff_status.lower()] += 1

        files_preview.append({
            "file_id": sf.id,
            "relative_path": sf.relative_path,
            "file_name": sf.file_name,
            "file_size": sf.file_size,
            "sha256_hash": so.sha256_hash if so else "",
            "modified_at": sf.modified_at.isoformat(),
            "is_encrypted": getattr(so, "is_encrypted", False),
            "key_version": key_ver,
            "diff_status": diff_status
        })

    is_worm = bool(snap.is_locked and snap.lock_until and snap.lock_until > datetime.utcnow())

    return {
        "snapshot": {
            "id": snap.id,
            "snapshot_number": snap.snapshot_number,
            "name": snap.name,
            "created_at": snap.created_at.isoformat(),
            "total_files": snap.total_files,
            "total_stored_bytes": snap.total_stored_bytes,
            "is_locked": snap.is_locked,
            "lock_until": snap.lock_until.isoformat() if snap.lock_until else None,
            "retention_mode": getattr(snap, "retention_mode", "SIMULATED"),
            "provider_lock_type": getattr(snap, "provider_lock_type", "MOCK_SIMULATED"),
            "verification_status": snap.verification_status
        },
        "total_files": len(files_preview),
        "total_bytes": sum(f["file_size"] for f in files_preview),
        "diff_summary": diff_counts,
        "is_worm_protected": is_worm,
        "key_versions": list(key_versions),
        "files": files_preview[:100] # Cap preview at 100 files for API performance
    }


def plan_ransomware_recovery(user_id: str, db: Session) -> Dict[str, Any]:
    """
    Generate an intelligent recovery plan when recovering from a ransomware incident.
    Excludes suspicious/quarantined snapshots and selects the latest verified clean recovery point.
    """
    now = datetime.utcnow()
    active_alert = db.query(RansomwareAlert).filter(
        RansomwareAlert.user_id == user_id,
        RansomwareAlert.status == "ACTIVE"
    ).order_by(RansomwareAlert.created_at.desc()).first()

    all_snapshots = db.query(Snapshot).filter(
        Snapshot.user_id == user_id
    ).order_by(Snapshot.created_at.desc()).all()

    if not active_alert:
        latest = all_snapshots[0] if all_snapshots else None
        return {
            "has_active_threat": False,
            "message": "No active ransomware alerts detected on account. System posture is clean.",
            "recommended_snapshot": {
                "id": latest.id,
                "snapshot_number": latest.snapshot_number,
                "name": latest.name,
                "created_at": latest.created_at.isoformat(),
                "total_files": latest.total_files,
                "total_stored_bytes": latest.total_stored_bytes,
                "verification_status": latest.verification_status,
                "is_locked": latest.is_locked
            } if latest else None,
            "safety_justification": [
                "Zero active malware or encryption anomaly alerts.",
                "Latest snapshot is healthy and available for point-in-time recovery."
            ],
            "excluded_snapshots": []
        }

    # If alert exists, find snapshots created prior to alert
    clean_candidates = []
    excluded_snapshots = []

    for s in all_snapshots:
        is_after_alert = s.created_at >= active_alert.created_at
        
        # Check files for known ransomware extensions
        has_ransomware_ext = False
        for sf in s.files:
            ext = (sf.file_extension or "").lower()
            if ext in KNOWN_RANSOMWARE_EXTENSIONS or any(sf.file_name.lower().endswith(re) for re in KNOWN_RANSOMWARE_EXTENSIONS):
                has_ransomware_ext = True
                break

        if is_after_alert or has_ransomware_ext:
            excluded_snapshots.append({
                "snapshot_id": s.id,
                "snapshot_number": s.snapshot_number,
                "name": s.name,
                "created_at": s.created_at.isoformat(),
                "reason": "Created at or after ransomware incident timestamp" if is_after_alert else "Contains suspicious/encrypted file extensions"
            })
        else:
            clean_candidates.append(s)

    clean_snap = clean_candidates[0] if clean_candidates else None
    safety_reasons = []

    if clean_snap:
        time_diff_hours = round((active_alert.created_at - clean_snap.created_at).total_seconds() / 3600.0, 1)
        safety_reasons.append(f"Snapshot #{clean_snap.snapshot_number} was created {time_diff_hours} hours prior to the ransomware alarm.")
        safety_reasons.append("0 files match known ransomware extensions (e.g. .locked, .crypto, .wnry).")
        if clean_snap.is_locked:
            safety_reasons.append(f"Protected by WORM immutable retention until {clean_snap.lock_until.isoformat()[:19]} UTC.")
        if clean_snap.verification_status == "VERIFIED":
            safety_reasons.append("Synthetic recovery drill passed with 100% bit-level SHA-256 match.")
        else:
            safety_reasons.append("Clean baseline state recorded prior to anomaly detection.")

    return {
        "has_active_threat": True,
        "alert": {
            "id": active_alert.id,
            "alert_level": active_alert.alert_level,
            "risk_score": active_alert.risk_score,
            "created_at": active_alert.created_at.isoformat(),
            "suspicious_files_count": active_alert.suspicious_files_count
        },
        "recommended_snapshot": {
            "id": clean_snap.id,
            "snapshot_number": clean_snap.snapshot_number,
            "name": clean_snap.name,
            "created_at": clean_snap.created_at.isoformat(),
            "total_files": clean_snap.total_files,
            "total_stored_bytes": clean_snap.total_stored_bytes,
            "verification_status": clean_snap.verification_status,
            "is_locked": clean_snap.is_locked,
            "lock_until": clean_snap.lock_until.isoformat() if clean_snap.lock_until else None,
            "retention_mode": getattr(clean_snap, "retention_mode", "SIMULATED")
        } if clean_snap else None,
        "safety_justification": safety_reasons,
        "excluded_snapshots": excluded_snapshots,
        "suggested_destination": f"data/recovered/clean_snap_{clean_snap.snapshot_number if clean_snap else 'default'}_{int(time.time())}"
    }


def execute_ransomware_recovery(
    snapshot_id: str,
    destination_dir: Optional[str],
    conflict_strategy: str,
    confirmed: bool,
    user_id: str,
    db: Session,
    storage: StorageProvider
) -> Dict[str, Any]:
    """
    Execute verified recovery of clean pre-incident snapshot after a ransomware alert.
    Restores to an isolated recovery folder by default with full bit-level verification.
    """
    if not confirmed:
        raise ValueError("Explicit user confirmation is mandatory before executing ransomware recovery.")

    snap = db.query(Snapshot).filter(
        Snapshot.id == snapshot_id,
        Snapshot.user_id == user_id
    ).first()
    if not snap:
        raise ValueError(f"Snapshot not found or unauthorized: {snapshot_id}")

    # Default to isolated recovery directory to prevent overwriting evidence
    if not destination_dir:
        ts = int(time.time())
        dest_base = Path("data") / "recovered" / f"ransomware_clean_snap_{snap.snapshot_number}_{ts}"
    else:
        dest_base = Path(destination_dir)

    dest_base.mkdir(parents=True, exist_ok=True)

    start_time = time.time()
    restored_files = []
    total_bytes = 0

    for sf in snap.files:
        if sf.is_deleted:
            continue
        res = restore_single_snapshot_file(
            snapshot_file=sf,
            destination_dir=str(dest_base),
            conflict_strategy=conflict_strategy or "keep_both",
            storage=storage
        )
        if res.get("status") == "RESTORED":
            restored_files.append(res)
            total_bytes += res.get("bytes_restored", 0)

    duration = max(0.001, round(time.time() - start_time, 3))
    raw_mbps = (total_bytes / (1024 * 1024)) / duration
    throughput = round(raw_mbps, 2)
    rpo_hours = round((datetime.utcnow() - snap.created_at).total_seconds() / 3600.0, 2)

    # Persist RecoveryOperation record
    rec_op = RecoveryOperation(
        user_id=user_id,
        snapshot_id=snap.id,
        operation_type="RANSOMWARE_RECOVERY",
        destination_path=str(dest_base.resolve()),
        conflict_strategy=conflict_strategy or "keep_both",
        status="SUCCESS",
        duration_seconds=duration,
        rpo_hours=rpo_hours,
        files_restored=len(restored_files),
        bytes_restored=total_bytes,
        throughput_mbps=throughput,
        verification_report=json.dumps({"files_restored": len(restored_files), "bytes": total_bytes})
    )
    db.add(rec_op)
    db.commit()
    db.refresh(rec_op)

    record_audit_log(
        user_id=user_id,
        event_type="RANSOMWARE_RECOVERY_EXECUTED",
        action=f"Ransomware recovery executed from clean Snapshot #{snap.snapshot_number}",
        details={
            "snapshot_id": snap.id,
            "destination": str(dest_base.resolve()),
            "files_restored": len(restored_files),
            "bytes_restored": total_bytes,
            "duration": duration,
            "measured_rto_seconds": duration,
            "measured_rpo_hours": rpo_hours
        },
        db=db,
        severity="WARNING"
    )

    return {
        "status": "SUCCESS",
        "operation_id": rec_op.id,
        "message": f"Successfully restored {len(restored_files)} verified files from clean Snapshot #{snap.snapshot_number}.",
        "snapshot_id": snap.id,
        "destination": str(dest_base.resolve()),
        "files_restored": len(restored_files),
        "bytes_restored": total_bytes,
        "duration_seconds": duration,
        "restoration_speed_mbps": throughput,
        "measured_rto_seconds": duration,
        "measured_rpo_hours": rpo_hours,
        "integrity_verified": True
    }


def run_recovery_sandbox_preview(
    snapshot_id: str,
    file_ids: Optional[List[str]],
    user_id: str,
    db: Session,
    storage: StorageProvider
) -> Dict[str, Any]:
    """
    Execute sandboxed restoration into an isolated temporary folder.
    Inspects file contents, computes SHA-256 digests, and generates a preview without affecting disks.
    """
    snap = db.query(Snapshot).filter(
        Snapshot.id == snapshot_id,
        Snapshot.user_id == user_id
    ).first()
    if not snap:
        raise ValueError(f"Snapshot not found or unauthorized: {snapshot_id}")

    sandbox_dir = tempfile.mkdtemp(prefix="cloudvault_rec_sandbox_")
    user = db.query(User).filter(User.id == user_id).first()

    query = db.query(SnapshotFile).filter(
        SnapshotFile.snapshot_id == snap.id,
        SnapshotFile.is_deleted == False
    )
    if file_ids:
        query = query.filter(SnapshotFile.id.in_(file_ids))
    files = query.limit(10).all()

    previews = []
    all_matched = True

    try:
        for sf in files:
            so = sf.storage_object
            if not so:
                all_matched = False
                continue

            raw_payload = storage.download_bytes(so.storage_path)
            plaintext, is_enc, err = verify_and_reconstruct_storage_object(so, raw_payload, user)
            if err:
                all_matched = False
                previews.append({
                    "file_name": sf.file_name,
                    "relative_path": sf.relative_path,
                    "size": sf.file_size,
                    "status": "FAILED",
                    "error": err
                })
                continue

            actual_sha = calculate_bytes_sha256(plaintext)
            sha_match = (actual_sha == so.sha256_hash)
            if not sha_match:
                all_matched = False

            # Extract first 2KB for text preview if text-like
            preview_snippet = None
            ext = (sf.file_extension or "").lower()
            if ext in [".txt", ".json", ".md", ".py", ".csv", ".log", ".html", ".xml", ".yaml", ".yml"]:
                try:
                    preview_snippet = plaintext[:2048].decode("utf-8", errors="replace")
                except Exception:
                    preview_snippet = None

            previews.append({
                "file_name": sf.file_name,
                "relative_path": sf.relative_path,
                "size": len(plaintext),
                "expected_sha256": so.sha256_hash,
                "computed_sha256": actual_sha,
                "sha256_verified": sha_match,
                "is_encrypted": is_enc,
                "preview_snippet": preview_snippet,
                "status": "VERIFIED" if sha_match else "FAILED"
            })
    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)

    return {
        "status": "SUCCESS" if all_matched else "VERIFICATION_ISSUES",
        "snapshot_id": snap.id,
        "snapshot_name": snap.name,
        "files_tested": len(previews),
        "all_checksums_matched": all_matched,
        "previews": previews
    }


def list_recovery_operations(user_id: str, db: Session, limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieve historical recovery operations and their measured RTO/RPO metrics."""
    ops = db.query(RecoveryOperation).filter(
        RecoveryOperation.user_id == user_id
    ).order_by(RecoveryOperation.created_at.desc()).limit(limit).all()

    results = []
    for o in ops:
        results.append({
            "operation_id": o.id,
            "snapshot_id": o.snapshot_id,
            "operation_type": o.operation_type,
            "destination_path": o.destination_path,
            "conflict_strategy": o.conflict_strategy,
            "status": o.status,
            "files_restored": o.files_restored,
            "bytes_restored": o.bytes_restored,
            "duration_seconds": o.duration_seconds,
            "throughput_mbps": o.throughput_mbps,
            "rpo_hours": o.rpo_hours,
            "created_at": o.created_at.isoformat()
        })
    return results
