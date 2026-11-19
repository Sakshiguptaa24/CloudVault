import os
import json
from datetime import datetime, timedelta
from backend.app.models import User, BackupPlan, Snapshot, RansomwareAlert, AuditLog
from backend.app.services.ransomware_service import (
    calculate_shannon_entropy, analyze_file_list, scan_and_evaluate_plan
)
from backend.app.routers.security import (
    list_security_alerts, get_security_health, dismiss_security_alert,
    DismissAlertRequest, analyze_path_for_ransomware, AnalyzePathRequest
)
import pytest
from fastapi import HTTPException

def test_shannon_entropy_calculation():
    # 1. Uniform single byte -> 0 entropy
    zero_entropy = calculate_shannon_entropy(b"A" * 1024)
    assert zero_entropy == 0.0

    # 2. English text -> typical range 3.0 to 5.0
    text = b"CloudVault is an intelligent cloud backup and disaster recovery platform with deduplication."
    text_entropy = calculate_shannon_entropy(text)
    assert 3.0 <= text_entropy <= 5.0

    # 3. High-entropy random data -> > 7.5 bits/byte
    random_bytes = os.urandom(2048)
    rand_entropy = calculate_shannon_entropy(random_bytes)
    assert rand_entropy >= 7.6

def test_high_entropy_alone_does_not_trigger_quarantine():
    """STRICT REQUIREMENT: High entropy alone must never trigger automatic quarantine."""
    # Scenario: User has compressed/image files with naturally high entropy
    normal_files = [
        {"file_name": "photo1.jpg", "file_extension": ".jpg", "entropy": 7.8},
        {"file_name": "archive.zip", "file_extension": ".zip", "entropy": 7.9},
        {"file_name": "data.csv", "file_extension": ".csv", "entropy": 4.1}
    ]
    analysis = analyze_file_list(normal_files)
    assert analysis["alert_level"] != "QUARANTINED"
    assert analysis["risk_score"] < 70

def test_simulated_ransomware_detection_and_quarantine(db_session):
    user = User(email="victim@university.edu", password_hash="hash", full_name="Victim User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Work Documents", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    # Pre-existing clean snapshot
    clean_snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Clean Prior State",
        is_locked=False,
        is_immutable=False
    )
    db_session.add(clean_snap)
    db_session.commit()

    # Simulated Ransomware payload: 8 files renamed with .locked and high entropy
    ransomware_files = []
    for i in range(8):
        ransomware_files.append({
            "file_name": f"document_{i}.docx.locked",
            "file_extension": ".locked",
            "entropy": 7.92
        })

    analysis = analyze_file_list(ransomware_files)
    assert analysis["risk_score"] >= 70
    assert analysis["alert_level"] == "QUARANTINED"
    assert ".locked" in analysis["matched_extensions"]

def test_security_router_apis(db_session):
    user = User(email="sec_user@university.edu", password_hash="hash", full_name="Sec User")
    db_session.add(user)
    db_session.commit()

    # 1. Health check when clean
    health = get_security_health(current_user=user, db=db_session)
    assert health["status"] == "HEALTHY"
    assert health["active_ransomware_alerts"] == 0

    # 2. Add an alert manually
    alert = RansomwareAlert(
        user_id=user.id,
        risk_score=75,
        alert_level="QUARANTINED",
        suspicious_files_count=10,
        average_entropy=7.85,
        matched_extensions=json.dumps([".locked"]),
        details=json.dumps(["Mass encryption detected"]),
        status="ACTIVE"
    )
    db_session.add(alert)
    db_session.commit()

    # Verify listed
    alerts_res = list_security_alerts(status="ACTIVE", current_user=user, db=db_session)
    assert alerts_res["total"] == 1
    assert alerts_res["alerts"][0]["risk_score"] == 75

    # 3. Dismiss alert
    req_dismiss = DismissAlertRequest(resolution_notes="Authorized test file encryption")
    dismiss_res = dismiss_security_alert(alert.id, req_dismiss, current_user=user, db=db_session)
    assert dismiss_res["status"] == "SUCCESS"

    # Verify dismissed in DB
    db_session.refresh(alert)
    assert alert.status == "DISMISSED"

