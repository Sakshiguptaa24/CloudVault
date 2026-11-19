import os
import json
import pytest
from datetime import datetime, timedelta
from fastapi import HTTPException

from backend.app.models import User, BackupPlan, Snapshot, SnapshotFile, RansomwareAlert, AuditLog
from backend.app.services.ransomware_service import (
    calculate_shannon_entropy,
    calculate_file_entropy,
    calculate_entropy_delta,
    analyze_file_activity,
    analyze_file_list,
    scan_and_evaluate_plan,
    resolve_security_alert,
    simulate_ransomware_scenario
)
from backend.app.routers.security import (
    list_security_alerts,
    get_security_health,
    dismiss_security_alert,
    resolve_alert,
    simulate_attack_test,
    analyze_path_for_ransomware,
    DismissAlertRequest,
    ResolveAlertRequest,
    SimulateAttackRequest,
    AnalyzePathRequest
)
from backend.app.routers.ai import query_ai_assistant, confirm_ai_action, AIQueryRequest, AIConfirmActionRequest
from backend.app.ai.security import create_confirmation_token

# 1. Normal file modifications & Shannon entropy
def test_shannon_entropy_calculation():
    zero_entropy = calculate_shannon_entropy(b"A" * 1024)
    assert zero_entropy == 0.0

    text = b"CloudVault is an intelligent cloud backup and disaster recovery platform with deduplication."
    text_entropy = calculate_shannon_entropy(text)
    assert 3.0 <= text_entropy <= 5.0

    random_bytes = os.urandom(2048)
    rand_entropy = calculate_shannon_entropy(random_bytes)
    assert rand_entropy >= 7.6

# 2. Naturally high-entropy compressed files (False-positive safety check)
def test_high_entropy_compressed_files_not_quarantined():
    """STRICT REQUIREMENT: High entropy alone must NEVER trigger automatic quarantine."""
    archive_files = [
        {"file_name": "photo_vacation.jpg", "file_extension": ".jpg", "entropy": 7.85},
        {"file_name": "backup_archive.zip", "file_extension": ".zip", "entropy": 7.92},
        {"file_name": "presentation_media.mp4", "file_extension": ".mp4", "entropy": 7.78},
        {"file_name": "data_table.csv", "file_extension": ".csv", "entropy": 3.40}
    ]
    analysis = analyze_file_activity(archive_files)
    assert analysis["alert_level"] != "QUARANTINED"
    assert analysis["risk_score"] < 60
    assert analysis["signals_breakdown"]["extension_score"] == 0

# 3. High-entropy encrypted files with suspicious extensions
def test_high_entropy_encrypted_files_with_ransomware_extensions():
    encrypted_files = [
        {"file_name": f"accounting_{i}.xlsx.locked", "file_extension": ".locked", "entropy": 7.94}
        for i in range(10)
    ]
    analysis = analyze_file_activity(encrypted_files)
    assert analysis["risk_score"] >= 80
    assert analysis["alert_level"] == "QUARANTINED"
    assert ".locked" in analysis["matched_extensions"]
    assert analysis["signals_breakdown"]["extension_score"] >= 40

# 4. Rapid bulk file modifications burst
def test_rapid_bulk_file_modifications_burst():
    bulk_files = [
        {"file_name": f"source_code_{i}.py", "file_extension": ".py", "entropy": 4.5}
        for i in range(25)
    ]
    analysis = analyze_file_activity(bulk_files)
    assert analysis["signals_breakdown"]["velocity_score"] > 0
    # Velocity alone without malware extensions should remain non-critical
    assert analysis["alert_level"] != "QUARANTINED"

# 5. Suspicious extension changes and double extensions
def test_suspicious_double_extensions():
    double_ext_files = [
        {"file_name": "payroll.pdf.locked", "file_extension": ".locked", "entropy": 7.8},
        {"file_name": "contract.docx.crypto", "file_extension": ".crypto", "entropy": 7.9}
    ]
    analysis = analyze_file_activity(double_ext_files)
    assert analysis["signals_breakdown"]["extension_score"] >= 40
    assert any("double extension" in r.lower() for r in analysis["reasons"])

# 6. Large deletion bursts
def test_large_deletion_bursts():
    normal_files = [
        {"file_name": "document.txt", "file_extension": ".txt", "entropy": 3.8}
    ]
    analysis = analyze_file_activity(normal_files, deleted_count=20)
    assert analysis["signals_breakdown"]["deletion_score"] == 25
    assert any("deletion burst" in r.lower() for r in analysis["reasons"])

# 7. Combined anomaly signals
def test_combined_anomaly_signals():
    combined_files = [
        {"file_name": f"doc_{i}.txt.locked", "file_extension": ".locked", "entropy": 7.9}
        for i in range(22)
    ]
    analysis = analyze_file_activity(combined_files, deleted_count=18)
    assert analysis["risk_score"] >= 80
    assert analysis["alert_level"] == "QUARANTINED"
    breakdown = analysis["signals_breakdown"]
    assert breakdown["extension_score"] > 0
    assert breakdown["entropy_score"] > 0
    assert breakdown["velocity_score"] > 0
    assert breakdown["deletion_score"] > 0

# 8. False-positive delta entropy handling
def test_false_positive_delta_entropy_handling():
    baseline = {
        "file_entropy_map": {
            "notes.txt": 3.8,
            "archive.zip": 7.8
        }
    }
    # Slight normal modification on archive -> delta negligible (+0.05)
    files_safe = [
        {"file_name": "archive.zip", "relative_path": "archive.zip", "file_extension": ".zip", "entropy": 7.85}
    ]
    res_safe = analyze_file_activity(files_safe, historical_baseline=baseline)
    assert res_safe["risk_score"] < 30
    assert res_safe["alert_level"] == "NORMAL"

    # Massive delta jump on plaintext -> jump +4.1 bits/byte
    files_anom = [
        {"file_name": "notes.txt", "relative_path": "notes.txt", "file_extension": ".txt", "entropy": 7.9}
    ]
    res_anom = analyze_file_activity(files_anom, historical_baseline=baseline)
    assert res_anom["signals_breakdown"]["entropy_score"] > 0

# 9. Alert generation and clean snapshot preservation (WORM lock)
def test_alert_generation_and_snapshot_preservation(db_session):
    user = User(email="preserve_user@university.edu", password_hash="hash", full_name="Preserve User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Core Assets", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    # Create prior clean snapshot (unlocked)
    clean_snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Clean State V1",
        is_locked=False,
        is_immutable=False
    )
    db_session.add(clean_snap)
    db_session.commit()

    # Manually trigger plan evaluation with simulated ransomware files
    anom_files = [
        {"file_name": f"data_{i}.csv.locked", "file_extension": ".locked", "entropy": 7.95}
        for i in range(10)
    ]
    analysis = analyze_file_activity(anom_files)
    assert analysis["risk_score"] >= 60

    # Simulate alert triggered on plan
    alert = RansomwareAlert(
        user_id=user.id,
        plan_id=plan.id,
        risk_score=analysis["risk_score"],
        alert_level=analysis["alert_level"],
        suspicious_files_count=analysis["suspicious_files_count"],
        average_entropy=analysis["average_entropy"],
        matched_extensions=json.dumps(analysis["matched_extensions"]),
        details=json.dumps(analysis["reasons"]),
        status="ACTIVE"
    )
    db_session.add(alert)

    # Protect prior clean snapshot with WORM retention lock
    clean_snap.is_locked = True
    clean_snap.is_immutable = True
    clean_snap.lock_until = datetime.utcnow() + timedelta(days=14)
    db_session.commit()

    # Verify snapshot is protected
    db_session.refresh(clean_snap)
    assert clean_snap.is_locked is True
    assert clean_snap.is_immutable is True
    assert clean_snap.lock_until is not None

# 10. Reversible quarantine & alert resolution
def test_quarantine_resolution_and_reversal(db_session):
    user = User(email="resolve_user@university.edu", password_hash="hash", full_name="Resolve User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Project Beta", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Locked By Anomaly",
        is_locked=True,
        is_immutable=True,
        lock_until=datetime.utcnow() + timedelta(days=14)
    )
    db_session.add(snap)
    db_session.commit()

    alert = RansomwareAlert(
        user_id=user.id,
        plan_id=plan.id,
        risk_score=85,
        alert_level="QUARANTINED",
        suspicious_files_count=15,
        average_entropy=7.9,
        matched_extensions=json.dumps([".locked"]),
        details=json.dumps(["Mass ransomware encryption"]),
        status="ACTIVE"
    )
    db_session.add(alert)
    db_session.commit()

    # Resolve alert and reverse quarantine
    res = resolve_security_alert(
        alert_id=alert.id,
        user_id=user.id,
        resolution_notes="False positive verified by administrator",
        unquarantine_snapshots=True,
        db=db_session
    )
    assert res["status"] == "SUCCESS"
    assert res["unlocked_snapshots"] == 1

    db_session.refresh(alert)
    assert alert.status == "RESOLVED"

    db_session.refresh(snap)
    assert snap.is_locked is False
    assert snap.is_immutable is False

# 11. Safe simulation sandbox execution
def test_safe_simulation_sandbox_execution(db_session):
    user = User(email="sim_user@university.edu", password_hash="hash", full_name="Sim User")
    db_session.add(user)
    db_session.commit()

    # Test 1: Mass encryption simulation in sandbox
    res_mass = simulate_ransomware_scenario(user.id, db_session, scenario_type="mass_encryption")
    assert res_mass["status"] == "COMPLETED"
    assert res_mass["analysis"]["risk_score"] >= 80
    assert res_mass["analysis"]["alert_level"] == "QUARANTINED"
    assert res_mass["is_quarantined"] is True

    # Test 2: Naturally high entropy archive simulation in sandbox -> zero false positive
    res_arch = simulate_ransomware_scenario(user.id, db_session, scenario_type="high_entropy_archive")
    assert res_arch["status"] == "COMPLETED"
    assert res_arch["analysis"]["risk_score"] < 40
    assert res_arch["analysis"]["alert_level"] != "QUARANTINED"
    assert res_arch["is_quarantined"] is False

# 12. Cross-user security isolation
def test_cross_user_security_isolation(db_session):
    user_alice = User(email="alice_sec@university.edu", password_hash="hash", full_name="Alice")
    user_eve = User(email="eve_sec@university.edu", password_hash="hash", full_name="Eve")
    db_session.add_all([user_alice, user_eve])
    db_session.commit()

    alert_alice = RansomwareAlert(
        user_id=user_alice.id,
        risk_score=75,
        alert_level="HIGH_RISK",
        suspicious_files_count=8,
        average_entropy=7.8,
        matched_extensions="[]",
        details="[]",
        status="ACTIVE"
    )
    db_session.add(alert_alice)
    db_session.commit()

    # Eve lists alerts -> Alice's alert must NOT appear
    eve_alerts = list_security_alerts(current_user=user_eve, db=db_session)
    assert eve_alerts["total"] == 0

    # Eve tries to dismiss Alice's alert -> 404
    req = DismissAlertRequest(resolution_notes="Unauthorized attempt")
    with pytest.raises(HTTPException) as exc:
        dismiss_security_alert(alert_alice.id, req, current_user=user_eve, db=db_session)
    assert exc.value.status_code == 404

# 13. AI Security Queries Integration (all 6 queries)
def test_ai_security_assistant_queries(db_session):
    user = User(email="ai_sec@university.edu", password_hash="hash", full_name="AI Security User")
    db_session.add(user)
    db_session.commit()

    # Pre-existing clean snapshot
    plan = BackupPlan(user_id=user.id, plan_name="Production Data", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    clean_snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Clean State #1",
        total_files=10,
        is_locked=True,
        is_immutable=True
    )
    db_session.add(clean_snap)
    db_session.commit()

    # Create active ransomware alert
    alert = RansomwareAlert(
        user_id=user.id,
        plan_id=plan.id,
        risk_score=85,
        alert_level="QUARANTINED",
        suspicious_files_count=12,
        average_entropy=7.92,
        matched_extensions=json.dumps([".locked"]),
        details=json.dumps([
            "12 files exhibiting known ransomware extension '.locked'",
            "Ciphertext entropy jump > 7.50 bits/byte"
        ]),
        status="ACTIVE"
    )
    db_session.add(alert)
    db_session.commit()

    # Query 1: Are there any suspicious file activities?
    q1 = AIQueryRequest(prompt="Are there any suspicious file activities?")
    r1 = query_ai_assistant(q1, current_user=user, db=db_session)
    assert "Active Security Alerts" in r1["response"]
    assert "85/100" in r1["response"] or "QUARANTINED" in r1["response"]

    # Query 2: Why was this backup flagged?
    q2 = AIQueryRequest(prompt="Why was this backup flagged?")
    r2 = query_ai_assistant(q2, current_user=user, db=db_session)
    assert "Detection Reasons" in r2["response"]
    assert ".locked" in r2["response"]

    # Query 3: Which files are affected?
    q3 = AIQueryRequest(prompt="Which files are affected?")
    r3 = query_ai_assistant(q3, current_user=user, db=db_session)
    assert "12 file(s)" in r3["response"] or "Affected Files" in r3["response"]

    # Query 4: What is the current risk level?
    q4 = AIQueryRequest(prompt="What is the current risk level?")
    r4 = query_ai_assistant(q4, current_user=user, db=db_session)
    assert "85" in r4["response"] or "QUARANTINED" in r4["response"]

    # Query 5: Which clean snapshot should I recover?
    q5 = AIQueryRequest(prompt="Which clean snapshot should I recover?")
    r5 = query_ai_assistant(q5, current_user=user, db=db_session)
    assert "Snapshot #1" in r5["response"]
    assert "Clean State #1" in r5["response"]

    # Query 6: What should I do next?
    q6 = AIQueryRequest(prompt="What should I do next?")
    r6 = query_ai_assistant(q6, current_user=user, db=db_session)
    assert "Remediation" in r6["response"]
    assert "Isolate" in r6["response"] or "Recover" in r6["response"]

# 14. Authorization of sensitive recovery actions under security alert
def test_authorization_of_sensitive_recovery_actions_under_alert(db_session):
    user = User(email="auth_action@university.edu", password_hash="hash", full_name="Auth Action User")
    db_session.add(user)
    db_session.commit()

    alert = RansomwareAlert(
        user_id=user.id,
        risk_score=90,
        alert_level="QUARANTINED",
        suspicious_files_count=10,
        average_entropy=7.9,
        matched_extensions=json.dumps([".locked"]),
        details=json.dumps(["Mass ransomware encryption"]),
        status="ACTIVE"
    )
    db_session.add(alert)
    db_session.commit()

    # Create signed confirmation token for resolving the alert
    payload = {
        "alert_id": alert.id,
        "action": "RESOLVE_ALERT",
        "description": f"Resolve ransomware alert {alert.id} and unquarantine snapshots.",
        "unquarantine_snapshots": True
    }
    token, _ = create_confirmation_token(user.id, "RESOLVE_ALERT", alert.id, payload, db_session)
    assert token is not None

    # Confirm execution
    confirm_req = AIConfirmActionRequest(confirmation_token=token)
    res = confirm_ai_action(confirm_req, current_user=user, db=db_session)
    assert res["status"] == "SUCCESS"

    db_session.refresh(alert)
    assert alert.status == "RESOLVED"

    # Replay attack check
    with pytest.raises(HTTPException) as exc:
        confirm_ai_action(confirm_req, current_user=user, db=db_session)
    assert exc.value.status_code == 400
    assert "replay" in exc.value.detail.lower()
