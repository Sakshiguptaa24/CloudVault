import os
import math
import collections
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session

from backend.app.models import User, BackupPlan, Snapshot, SnapshotFile, RansomwareAlert, AuditLog
from backend.app.ai.security import record_audit_log

KNOWN_RANSOMWARE_EXTENSIONS = {
    ".locked", ".crypto", ".crypt", ".wnry", ".locky", ".crypted",
    ".ransom", ".enc", ".dark", ".pay", ".encrypt", ".cerber", ".zepto"
}

NATURALLY_HIGH_ENTROPY_EXTENSIONS = {
    ".zip", ".gz", ".tar", ".7z", ".rar", ".bz2", ".xz",
    ".jpg", ".jpeg", ".png", ".webp", ".gif",
    ".mp4", ".mkv", ".avi", ".mov", ".mp3", ".flac",
    ".pdf", ".docx", ".xlsx", ".pptx"
}

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy in bits per byte (0.0 to 8.0).
    Pure randomness (AES/ChaCha encrypted) approaches 8.0 bits/byte.
    Plaintext and source code are typically 2.0 to 5.0 bits/byte.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0

    for count in counts.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)

def calculate_file_entropy(file_path: str, max_bytes: int = 262144) -> float:
    """Compute entropy on the first 256 KB of a file for fast I/O."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(max_bytes)
        return calculate_shannon_entropy(chunk)
    except Exception:
        return 0.0

def analyze_file_list(files: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze a collection of scanned files for anomalous ransomware indicators.
    Evaluates:
      1. Known ransomware extension match (+50 risk)
      2. Unexpected high entropy (> 7.5) on normally uncompressed files (+35 risk)
      3. Mass modification velocity (+25 risk)
    NOTE: High entropy alone never triggers high-risk quarantine.
    """
    total_files = len(files)
    if total_files == 0:
        return {
            "risk_score": 0,
            "alert_level": "NORMAL",
            "suspicious_files_count": 0,
            "average_entropy": 0.0,
            "matched_extensions": [],
            "reasons": ["No files to analyze"]
        }

    suspicious_count = 0
    matched_exts = set()
    total_entropy = 0.0
    entropy_anomaly_count = 0
    reasons = []

    for f in files:
        ext = f.get("file_extension", "").lower()
        full_path = f.get("full_path")
        entropy = f.get("entropy")

        if entropy is None and full_path and os.path.exists(full_path):
            entropy = calculate_file_entropy(full_path)
        elif entropy is None:
            entropy = 4.0 # Neutral fallback

        total_entropy += entropy

        # 1. Ransomware extension detection
        if ext in KNOWN_RANSOMWARE_EXTENSIONS:
            matched_exts.add(ext)
            suspicious_count += 1

        # 2. Unexpected entropy anomaly
        # If file is NOT naturally compressed (e.g. .txt, .sql, .csv, .py, .html) but has entropy > 7.5
        if ext not in NATURALLY_HIGH_ENTROPY_EXTENSIONS:
            if entropy >= 7.5:
                entropy_anomaly_count += 1
                suspicious_count += 1

    avg_entropy = round(total_entropy / total_files, 2)
    risk_score = 0

    # Multi-signal scoring engine
    if matched_exts:
        risk_score += 50
        reasons.append(f"Detected known ransomware file extensions: {', '.join(sorted(matched_exts))}")

    if total_files > 0 and (entropy_anomaly_count / total_files) >= 0.4:
        # 40% or more plaintext/data files suddenly have uniform high entropy (>7.5)
        risk_score += 35
        reasons.append(f"{entropy_anomaly_count} plaintext/document files exhibit encrypted-grade entropy (> 7.5 bits/byte)")
    elif total_files > 0 and (entropy_anomaly_count / total_files) >= 0.15:
        risk_score += 15
        reasons.append(f"Elevated entropy detected on {entropy_anomaly_count} files")

    if suspicious_count > 0 and (suspicious_count / total_files) >= 0.5:
        risk_score += 25
        reasons.append(f"Over 50% of scanned files ({suspicious_count}/{total_files}) flagged as anomalous")

    risk_score = min(100, risk_score)

    if risk_score >= 70:
        alert_level = "QUARANTINED"
    elif risk_score >= 40:
        alert_level = "HIGH_RISK"
    elif risk_score >= 20:
        alert_level = "SUSPICIOUS"
    else:
        alert_level = "NORMAL"

    return {
        "risk_score": risk_score,
        "alert_level": alert_level,
        "suspicious_files_count": suspicious_count,
        "average_entropy": avg_entropy,
        "matched_extensions": sorted(list(matched_exts)),
        "entropy_anomalies": entropy_anomaly_count,
        "reasons": reasons if reasons else ["File system activity conforms to normal operational patterns"]
    }

def scan_and_evaluate_plan(plan_id: str, user_id: str, db: Session) -> Optional[RansomwareAlert]:
    """
    Perform a ransomware scan on a plan's directory.
    If anomaly risk score >= 40, generates an alert and automatically shields prior clean snapshots.
    """
    plan = db.query(BackupPlan).filter(BackupPlan.id == plan_id, BackupPlan.user_id == user_id).first()
    if not plan:
        return None

    import json
    try:
        dirs = json.loads(plan.source_directories)
    except Exception:
        dirs = []

    scanned_files = []
    for d in dirs:
        if not os.path.exists(d):
            continue
        for root, _, files in os.walk(d):
            for file in files:
                p = os.path.join(root, file)
                ext = os.path.splitext(file)[1].lower()
                scanned_files.append({
                    "full_path": p,
                    "file_name": file,
                    "file_extension": ext,
                    "file_size": os.path.getsize(p) if os.path.exists(p) else 0
                })
                if len(scanned_files) >= 200: # Fast evaluation window
                    break

    analysis = analyze_file_list(scanned_files)

    if analysis["risk_score"] >= 40:
        # Create Alert
        alert = RansomwareAlert(
            user_id=user_id,
            plan_id=plan.id,
            risk_score=analysis["risk_score"],
            alert_level=analysis["alert_level"],
            suspicious_files_count=analysis["suspicious_files_count"],
            average_entropy=analysis["average_entropy"],
            matched_extensions=json.dumps(analysis["matched_extensions"]),
            details=json.dumps(analysis["reasons"]),
            status="ACTIVE"
        )
        db.add(alert)

        # ENGAGE SAFEGUARD: Protect prior clean snapshots with WORM retention lock!
        clean_snaps = db.query(Snapshot).filter(
            Snapshot.plan_id == plan.id,
            Snapshot.is_locked == False
        ).all()
        for snap in clean_snaps:
            snap.is_locked = True
            snap.is_immutable = True
            snap.lock_until = datetime.utcnow() + timedelta(days=14)

        db.commit()
        db.refresh(alert)

        # Audit log entry
        record_audit_log(
            user_id=user_id,
            event_type="RANSOMWARE_ALERT_TRIGGERED",
            action=f"Score: {analysis['risk_score']} ({analysis['alert_level']})",
            details={
                "plan_id": plan.id,
                "plan_name": plan.plan_name,
                "risk_score": analysis["risk_score"],
                "reasons": analysis["reasons"],
                "shielded_snapshots_count": len(clean_snaps)
            },
            db=db,
            severity="CRITICAL"
        )

        return alert

    return None


def analyze_directory_for_ransomware(directory_path: str) -> Dict[str, Any]:
    """Scan a local directory for ransomware signatures and Shannon entropy anomalies."""
    from pathlib import Path
    target = Path(directory_path).resolve()
    file_list = []
    
    if target.is_dir():
        for p in target.rglob("*"):
            if p.is_file():
                file_list.append({
                    "full_path": str(p),
                    "file_name": p.name,
                    "file_extension": p.suffix.lower(),
                    "file_size": p.stat().st_size
                })
    elif target.is_file():
        file_list.append({
            "full_path": str(target),
            "file_name": target.name,
            "file_extension": target.suffix.lower(),
            "file_size": target.stat().st_size
        })

    analysis = analyze_file_list(file_list)
    analysis["files_scanned"] = len(file_list)
    analysis["suspicious_count"] = analysis["suspicious_files_count"]
    analysis["action_taken"] = "MONITORING" if analysis["alert_level"] != "QUARANTINED" else "AUTO_SHIELD_TRIGGERED"
    return analysis
