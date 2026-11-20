import os
import json
import pytest
from pathlib import Path
from datetime import datetime, timedelta
from fastapi import HTTPException

from backend.app.models import (
    User, BackupPlan, Snapshot, SnapshotFile, StorageObject,
    DRDrill, RecoveryOperation, RansomwareAlert, BackupJob
)
from backend.app.auth import get_password_hash
from backend.app.storage import get_storage_provider
from backend.app.services.backup_service import backup_single_file, execute_backup_plan
from backend.app.services.restore_service import (
    restore_file_by_id, restore_snapshot, restore_single_snapshot_file
)
from backend.app.services.crypto_service import (
    derive_user_kek, rotate_user_kek
)
from backend.app.services.dr_service import (
    run_advanced_synthetic_recovery_drill,
    get_point_in_time_preview,
    plan_ransomware_recovery,
    execute_ransomware_recovery,
    run_recovery_sandbox_preview,
    get_dr_command_center_telemetry
)
from backend.app.routers.recovery import lock_snapshot_worm, LockSnapshotRequest
from backend.app.ai.provider import RuleBasedLocalLLMProvider


def test_1_file_recovery_bit_level_sha256(db_session, tmp_path):
    """1. Test individual file recovery with bit-level SHA-256 verification and operation recording."""
    user = User(email="dr_user1@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="DR User 1", encryption_salt="salt_dr_001")
    db_session.add(user)
    db_session.commit()

    src_dir = tmp_path / "src1"
    src_dir.mkdir()
    test_file = src_dir / "thesis_final.pdf"
    content = b"%PDF-1.4 Mock Thesis Cryptographic File Contents for Bit-Level Check 123456789"
    test_file.write_bytes(content)

    plan = BackupPlan(
        user_id=user.id,
        plan_name="Research Plan",
        source_directories=json.dumps([str(src_dir)]),
        encryption_enabled=False
    )
    db_session.add(plan)
    db_session.commit()

    storage = get_storage_provider()
    execute_backup_plan(plan.id, user.id, db_session, storage)

    snap = db_session.query(Snapshot).filter(Snapshot.user_id == user.id).first()
    assert snap is not None
    sf = db_session.query(SnapshotFile).filter(SnapshotFile.snapshot_id == snap.id).first()
    assert sf is not None

    # Restore to isolated destination
    dest_dir = tmp_path / "restored1"
    dest_dir.mkdir()
    res = restore_file_by_id(sf.id, str(dest_dir), "keep_both", db_session, storage, user_id=user.id)

    assert res["status"] == "RESTORED"
    restored_path = Path(res["path"])
    assert restored_path.exists()
    assert restored_path.read_bytes() == content


def test_2_folder_recovery_with_structure_preservation(db_session, tmp_path):
    """2. Test folder-scoped drill and directory hierarchy restore."""
    user = User(email="dr_user2@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="DR User 2", encryption_salt="salt_dr_002")
    db_session.add(user)
    db_session.commit()

    src_dir = tmp_path / "src2"
    sub_dir = src_dir / "subfolder" / "nested"
    sub_dir.mkdir(parents=True)
    (src_dir / "root.txt").write_text("Root document")
    (sub_dir / "nested_data.json").write_text('{"nested": true}')

    plan = BackupPlan(user_id=user.id, plan_name="Folder Plan", source_directories=json.dumps([str(src_dir)]))
    db_session.add(plan)
    db_session.commit()

    storage = get_storage_provider()
    execute_backup_plan(plan.id, user.id, db_session, storage)

    snap = db_session.query(Snapshot).filter(Snapshot.user_id == user.id).first()

    # Run folder-scoped recovery drill
    drill_res = run_advanced_synthetic_recovery_drill(
        user_id=user.id,
        db=db_session,
        storage=storage,
        snapshot_id=snap.id,
        drill_type="FOLDER",
        drill_scope="subfolder"
    )
    assert drill_res["status"] == "PASSED"
    assert drill_res["files_tested"] == 1
    assert "nested_data.json" in drill_res["verification_report"][0]["relative_path"]

    # Restore entire snapshot
    dest_dir = tmp_path / "restored2"
    dest_dir.mkdir()
    restore_res = restore_snapshot(snap.id, str(dest_dir), "keep_both", db_session, storage, user_id=user.id)
    assert restore_res["files_restored"] == 2
    assert (dest_dir / "subfolder" / "nested" / "nested_data.json").exists()


def test_3_historical_point_in_time_snapshot_recovery(db_session, tmp_path):
    """3. Test point-in-time recovery restoring older historical version over newer file."""
    user = User(email="dr_user3@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="DR User 3", encryption_salt="salt_dr_003")
    db_session.add(user)
    db_session.commit()

    src_dir = tmp_path / "src3"
    src_dir.mkdir()
    doc_file = src_dir / "proposal.md"
    
    # Version 1
    doc_file.write_text("# Proposal Version 1 - Clean Initial Draft")
    plan = BackupPlan(user_id=user.id, plan_name="PIT Plan", source_directories=json.dumps([str(src_dir)]))
    db_session.add(plan)
    db_session.commit()

    storage = get_storage_provider()
    execute_backup_plan(plan.id, user.id, db_session, storage)
    snap1 = db_session.query(Snapshot).filter(Snapshot.user_id == user.id).order_by(Snapshot.snapshot_number.asc()).first()

    # Version 2
    doc_file.write_text("# Proposal Version 2 - Accidental Corruption or Bad Edits")
    execute_backup_plan(plan.id, user.id, db_session, storage)
    snap2 = db_session.query(Snapshot).filter(Snapshot.user_id == user.id).order_by(Snapshot.snapshot_number.desc()).first()

    assert snap1.id != snap2.id

    # Preview diff of Version 1 against current file
    diff_prev = get_point_in_time_preview(snap1.id, str(src_dir), user.id, db_session)
    assert diff_prev["diff_summary"]["modified"] >= 1

    # Restore Historical Version 1 to isolated recovery folder
    dest_dir = tmp_path / "recovered_v1"
    dest_dir.mkdir()
    restore_snapshot(snap1.id, str(dest_dir), "keep_both", db_session, storage, user_id=user.id)

    restored_v1 = (dest_dir / "proposal.md").read_text()
    assert "Proposal Version 1" in restored_v1
    assert "Proposal Version 2" not in restored_v1


def test_4_encrypted_file_recovery_aes_gcm_envelope(db_session, tmp_path):
    """4. Test AES-256-GCM envelope encrypted file recovery, verifying DEK decryption and auth tag."""
    user = User(email="dr_enc@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Enc User", encryption_salt="salt_enc_999")
    db_session.add(user)
    db_session.commit()

    src_dir = tmp_path / "src_enc"
    src_dir.mkdir()
    secret_file = src_dir / "credentials.env"
    secret_file.write_text("DB_PASSWORD=SuperSecretZeroTrustPassword2026!")

    plan = BackupPlan(user_id=user.id, plan_name="Encrypted Plan", source_directories=json.dumps([str(src_dir)]), encryption_enabled=True)
    db_session.add(plan)
    db_session.commit()

    storage = get_storage_provider()
    execute_backup_plan(plan.id, user.id, db_session, storage)

    snap = db_session.query(Snapshot).filter(Snapshot.user_id == user.id).first()
    sf = snap.files[0]
    so = sf.storage_object

    assert so.is_encrypted is True
    assert so.encrypted_dek is not None
    assert so.dek_nonce is not None

    # Execute drill on encrypted snapshot
    drill_res = run_advanced_synthetic_recovery_drill(user.id, db_session, storage, snapshot_id=snap.id)
    assert drill_res["status"] == "PASSED"
    assert drill_res["verification_report"][0]["is_encrypted"] is True
    assert drill_res["verification_report"][0]["decrypted_successfully"] is True

    # Restore to disk
    dest_dir = tmp_path / "restored_enc"
    dest_dir.mkdir()
    res = restore_file_by_id(sf.id, str(dest_dir), "keep_both", db_session, storage, user_id=user.id)
    assert Path(res["path"]).read_text() == "DB_PASSWORD=SuperSecretZeroTrustPassword2026!"


def test_5_historical_encryption_key_version_recovery(db_session, tmp_path):
    """5. Test recovering files encrypted under older Key Encryption Key (v1) after key rotation to v2."""
    user = User(email="dr_key_rot@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Key Rot User", encryption_salt="salt_rot_dr")
    db_session.add(user)
    db_session.commit()

    src_dir = tmp_path / "src_rot"
    src_dir.mkdir()
    (src_dir / "v1_doc.txt").write_text("Created under Key Version 1")

    plan = BackupPlan(user_id=user.id, plan_name="Rot Plan", source_directories=json.dumps([str(src_dir)]), encryption_enabled=True)
    db_session.add(plan)
    db_session.commit()

    storage = get_storage_provider()
    execute_backup_plan(plan.id, user.id, db_session, storage)
    snap1 = db_session.query(Snapshot).filter(Snapshot.user_id == user.id).first()
    sf1 = snap1.files[0]
    assert sf1.storage_object.key_version == 1

    # Rotate KEK to version 2
    rotate_user_kek(user.id, db_session)
    assert user.current_key_version == 2

    # Backup new file under Key Version 2
    (src_dir / "v2_doc.txt").write_text("Created under Key Version 2")
    execute_backup_plan(plan.id, user.id, db_session, storage)
    snap2 = db_session.query(Snapshot).filter(Snapshot.user_id == user.id).order_by(Snapshot.snapshot_number.desc()).first()
    sf2 = [f for f in snap2.files if f.file_name == "v2_doc.txt"][0]
    assert sf2.storage_object.key_version == 2

    # Restore BOTH v1 and v2 files
    dest_dir = tmp_path / "restored_both_keys"
    dest_dir.mkdir()
    r1 = restore_file_by_id(sf1.id, str(dest_dir), "keep_both", db_session, storage, user_id=user.id)
    r2 = restore_file_by_id(sf2.id, str(dest_dir), "keep_both", db_session, storage, user_id=user.id)

    assert Path(r1["path"]).read_text() == "Created under Key Version 1"
    assert Path(r2["path"]).read_text() == "Created under Key Version 2"


def test_6_corrupted_object_detection_and_rejection(db_session, tmp_path):
    """6. Test corrupted test object detection, verifying drill marks FAILED and refuses false success."""
    user = User(email="dr_corrupt@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Corrupt User", encryption_salt="salt_corrupt")
    db_session.add(user)
    db_session.commit()

    src_dir = tmp_path / "src_corrupt"
    src_dir.mkdir()
    (src_dir / "integrity_test.bin").write_bytes(b"Valuable Critical Data" * 10)

    plan = BackupPlan(user_id=user.id, plan_name="Corrupt Plan", source_directories=json.dumps([str(src_dir)]))
    db_session.add(plan)
    db_session.commit()

    storage = get_storage_provider()
    execute_backup_plan(plan.id, user.id, db_session, storage)
    snap = db_session.query(Snapshot).filter(Snapshot.user_id == user.id).first()

    # Run drill with injected corruption
    res = run_advanced_synthetic_recovery_drill(
        user_id=user.id,
        db=db_session,
        storage=storage,
        snapshot_id=snap.id,
        drill_type="CORRUPTED_OBJECT_TEST",
        inject_corruption=True
    )

    assert res["status"] == "FAILED"
    assert "Integrity check failed" in res["error_details"] or "SHA-256" in res["error_details"]
    assert snap.verification_status == "FAILED"


def test_7_missing_storage_object_detection(db_session, tmp_path):
    """7. Test detection of missing storage object referenced in snapshot manifest."""
    user = User(email="dr_missing@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Missing User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Missing Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    snap = Snapshot(plan_id=plan.id, user_id=user.id, snapshot_number=1, name="Broken Snap", total_files=1, total_stored_bytes=100)
    db_session.add(snap)
    db_session.commit()

    # Snapshot file pointing to nonexistent storage object ID
    sf = SnapshotFile(
        snapshot_id=snap.id,
        storage_object_id="nonexistent-storage-object-id-000",
        relative_path="ghost.txt",
        file_name="ghost.txt",
        file_size=100,
        modified_at=datetime.utcnow()
    )
    db_session.add(sf)
    db_session.commit()

    storage = get_storage_provider()
    res = run_advanced_synthetic_recovery_drill(user.id, db_session, storage, snapshot_id=snap.id)

    assert res["status"] == "FAILED"
    assert "missing" in res["error_details"].lower()


def test_8_checksum_mismatch_detection_fails_safely(db_session, tmp_path):
    """8. Test checksum mismatch detection during restore raises ValueError and blocks corrupted write."""
    user = User(email="dr_mismatch@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Mismatch User")
    db_session.add(user)
    db_session.commit()

    src_dir = tmp_path / "src_mismatch"
    src_dir.mkdir()
    f = src_dir / "tampered.txt"
    f.write_text("Authentic original payload")

    plan = BackupPlan(user_id=user.id, plan_name="Mismatch Plan", source_directories=json.dumps([str(src_dir)]))
    db_session.add(plan)
    db_session.commit()

    storage = get_storage_provider()
    execute_backup_plan(plan.id, user.id, db_session, storage)
    snap = db_session.query(Snapshot).filter(Snapshot.user_id == user.id).first()
    sf = snap.files[0]
    so = sf.storage_object

    # Tamper with stored bytes in mock storage
    original_stored_bytes = storage.download_bytes(so.storage_path)
    # Tamper with byte content
    tampered_bytes = bytearray(original_stored_bytes)
    tampered_bytes[-1] ^= 0xFF
    storage.upload_bytes(bytes(tampered_bytes), so.storage_path)

    dest_dir = tmp_path / "restored_mismatch"
    dest_dir.mkdir()

    with pytest.raises(ValueError) as exc:
        restore_single_snapshot_file(sf, str(dest_dir), "keep_both", storage)
    assert "Integrity check failed" in str(exc.value)


def test_9_ransomware_safe_recovery_point_selection(db_session, tmp_path):
    """9. Test identifying pre-incident clean recovery point and excluding compromised snapshots."""
    user = User(email="dr_rw_clean@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="RW Clean User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="RW Clean Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    # 1. Clean Snapshot 1 (created 4 hours ago)
    t_clean = datetime.utcnow() - timedelta(hours=4)
    snap1 = Snapshot(plan_id=plan.id, user_id=user.id, snapshot_number=1, name="Clean Baseline", created_at=t_clean, is_locked=True, lock_until=t_clean + timedelta(days=30))
    db_session.add(snap1)
    db_session.commit()

    # 2. Ransomware incident triggered 1 hour ago
    t_alert = datetime.utcnow() - timedelta(hours=1)
    alert = RansomwareAlert(
        user_id=user.id,
        plan_id=plan.id,
        risk_score=95,
        alert_level="QUARANTINED",
        suspicious_files_count=15,
        created_at=t_alert,
        status="ACTIVE"
    )
    db_session.add(alert)
    db_session.commit()

    # 3. Compromised Snapshot 2 (created 30 mins ago, containing .locked files)
    t_bad = datetime.utcnow() - timedelta(minutes=30)
    snap2 = Snapshot(plan_id=plan.id, user_id=user.id, snapshot_number=2, name="Compromised Snap", created_at=t_bad)
    db_session.add(snap2)
    db_session.commit()

    sf_bad = SnapshotFile(
        snapshot_id=snap2.id,
        storage_object_id="dummy-so",
        relative_path="thesis.pdf.locked",
        file_name="thesis.pdf.locked",
        file_extension=".locked",
        file_size=500,
        modified_at=t_bad
    )
    db_session.add(sf_bad)
    db_session.commit()

    # Plan recovery
    rec_plan = plan_ransomware_recovery(user.id, db_session)
    assert rec_plan["has_active_threat"] is True
    assert rec_plan["recommended_snapshot"]["id"] == snap1.id
    assert rec_plan["recommended_snapshot"]["snapshot_number"] == 1
    assert any(ex["snapshot_id"] == snap2.id for ex in rec_plan["excluded_snapshots"])
    assert len(rec_plan["safety_justification"]) >= 2


def test_10_worm_protection_preserved_during_recovery(db_session, tmp_path):
    """10. Test that recovery operations respect and preserve active WORM locks without mutation."""
    user = User(email="dr_worm_pres@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="WORM Pres User")
    db_session.add(user)
    db_session.commit()

    src_dir = tmp_path / "src_worm"
    src_dir.mkdir()
    (src_dir / "locked_doc.txt").write_text("WORM immutable preserved record")

    plan = BackupPlan(user_id=user.id, plan_name="WORM Plan", source_directories=json.dumps([str(src_dir)]))
    db_session.add(plan)
    db_session.commit()

    storage = get_storage_provider()
    execute_backup_plan(plan.id, user.id, db_session, storage)
    snap = db_session.query(Snapshot).filter(Snapshot.user_id == user.id).first()

    # Lock with WORM
    lock_snapshot_worm(snap.id, LockSnapshotRequest(retention_days=14), current_user=user, db=db_session)
    db_session.refresh(snap)
    assert snap.is_immutable is True

    # Restore snapshot to separate location
    dest_dir = tmp_path / "restored_worm"
    dest_dir.mkdir()
    res = restore_snapshot(snap.id, str(dest_dir), "keep_both", db_session, storage, user_id=user.id)
    assert res["files_restored"] == 1

    # Verify locked snapshot remains untouched and locked
    db_session.refresh(snap)
    assert snap.is_immutable is True
    assert snap.is_locked is True


def test_11_recovery_sandbox_isolation_and_preview(db_session, tmp_path):
    """11. Test isolated recovery sandbox verifying SHA-256 and generating text preview snippets."""
    user = User(email="dr_sandbox@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Sandbox User")
    db_session.add(user)
    db_session.commit()

    src_dir = tmp_path / "src_sb"
    src_dir.mkdir()
    (src_dir / "sample.json").write_text('{"capstone": "CloudVault 2.0", "verified": true}')

    plan = BackupPlan(user_id=user.id, plan_name="Sandbox Plan", source_directories=json.dumps([str(src_dir)]))
    db_session.add(plan)
    db_session.commit()

    storage = get_storage_provider()
    execute_backup_plan(plan.id, user.id, db_session, storage)
    snap = db_session.query(Snapshot).filter(Snapshot.user_id == user.id).first()

    sb_res = run_recovery_sandbox_preview(snap.id, None, user.id, db_session, storage)
    assert sb_res["status"] == "SUCCESS"
    assert sb_res["all_checksums_matched"] is True
    assert len(sb_res["previews"]) == 1
    assert "CloudVault 2.0" in sb_res["previews"][0]["preview_snippet"]


def test_12_rto_and_rpo_real_measurements(db_session, tmp_path):
    """12. Test real RTO and RPO metrics calculation from actual drills and restores."""
    user = User(email="dr_metrics@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Metrics User")
    db_session.add(user)
    db_session.commit()

    src_dir = tmp_path / "src_met"
    src_dir.mkdir()
    (src_dir / "data.csv").write_text("col1,col2\nval1,val2\n" * 50)

    plan = BackupPlan(user_id=user.id, plan_name="Metrics Plan", source_directories=json.dumps([str(src_dir)]))
    db_session.add(plan)
    db_session.commit()

    storage = get_storage_provider()
    execute_backup_plan(plan.id, user.id, db_session, storage)
    snap = db_session.query(Snapshot).filter(Snapshot.user_id == user.id).first()

    # Run drill to establish measured RTO throughput
    run_advanced_synthetic_recovery_drill(user.id, db_session, storage, snapshot_id=snap.id)

    telemetry = get_dr_command_center_telemetry(user.id, db_session)
    assert telemetry["rpo"]["hours"] is not None
    assert telemetry["rpo"]["status"] == "HEALTHY"
    assert telemetry["rto"]["measured_speed_mbps"] > 0
    assert telemetry["rto"]["confidence"] == "HIGH_MEASURED"


def test_13_failed_recovery_handling_and_logging(db_session, tmp_path):
    """13. Test recording and telemetry tracking of failed recovery operations."""
    user = User(email="dr_fail_op@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Fail Op User")
    db_session.add(user)
    db_session.commit()

    # Record a failed recovery operation directly
    failed_op = RecoveryOperation(
        user_id=user.id,
        operation_type="SNAPSHOT_RESTORE",
        status="FAILED",
        duration_seconds=1.2,
        error_message="Destination directory access denied"
    )
    db_session.add(failed_op)
    db_session.commit()

    telemetry = get_dr_command_center_telemetry(user.id, db_session)
    assert telemetry["failed_operations_count"] >= 1


def test_14_ai_disaster_recovery_copilot_queries(db_session, tmp_path):
    """14. Test all 8 Phase 5 Disaster Recovery queries via AI Copilot."""
    user = User(email="dr_ai_eval@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="DR AI User", encryption_salt="salt_dr_ai")
    db_session.add(user)
    db_session.commit()

    src_dir = tmp_path / "src_ai"
    src_dir.mkdir()
    (src_dir / "notes.txt").write_text("AI DR Test Notes")

    plan = BackupPlan(user_id=user.id, plan_name="AI Plan", source_directories=json.dumps([str(src_dir)]))
    db_session.add(plan)
    db_session.commit()

    storage = get_storage_provider()
    execute_backup_plan(plan.id, user.id, db_session, storage)
    snap = db_session.query(Snapshot).filter(Snapshot.user_id == user.id).first()

    # Run drill so snap is verified
    run_advanced_synthetic_recovery_drill(user.id, db_session, storage, snapshot_id=snap.id)

    ai_provider = RuleBasedLocalLLMProvider()

    # 1. "Can I recover my latest backup?"
    q1 = ai_provider.process_query(user.id, "Can I recover my latest backup?", db_session)
    assert "Latest Backup Recoverability Status" in q1["response"]
    assert "Yes, your latest backup is healthy" in q1["response"]

    # 2. "What is my last verified recovery point?"
    q2 = ai_provider.process_query(user.id, "What is my last verified recovery point?", db_session)
    assert "Last Verified Recovery Point" in q2["response"]
    assert f"#{snap.snapshot_number}" in q2["response"]

    # 3. "How long would recovery take?"
    q3 = ai_provider.process_query(user.id, "How long would recovery take?", db_session)
    assert "Recovery Time Objective (RTO) Telemetry" in q3["response"]
    assert "MB/s" in q3["response"]

    # 4. "What is my current RPO?"
    q4 = ai_provider.process_query(user.id, "What is my current RPO?", db_session)
    assert "Recovery Point Objective (RPO) Status" in q4["response"]
    assert "hours" in q4["response"]

    # 5. "Which snapshots are safe after a ransomware incident?"
    q5 = ai_provider.process_query(user.id, "Which snapshots are safe after a ransomware incident?", db_session)
    assert "Ransomware Incident Safe Recovery Points" in q5["response"]

    # 6. "Did my last recovery drill pass?"
    q6 = ai_provider.process_query(user.id, "Did my last recovery drill pass?", db_session)
    assert "Latest Recovery Drill Status: ✅ PASSED" in q6["response"]

    # 7. "Which files failed integrity verification?"
    q7 = ai_provider.process_query(user.id, "Which files failed integrity verification?", db_session)
    assert "0 Integrity Verification Failures" in q7["response"]

    # 8. "What should I recover first?"
    q8 = ai_provider.process_query(user.id, "What should I recover first?", db_session)
    assert "Disaster Recovery Triage Protocol" in q8["response"]


def test_15_disaster_recovery_cross_tenant_isolation(db_session, tmp_path):
    """15. Test strict cross-tenant isolation for disaster recovery telemetry, drills and restores."""
    alice = User(email="alice_dr@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Alice")
    bob = User(email="bob_dr@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Bob")
    db_session.add_all([alice, bob])
    db_session.commit()

    src_dir = tmp_path / "alice_src"
    src_dir.mkdir()
    (src_dir / "alice_file.txt").write_text("Alice Confidential Data")

    plan = BackupPlan(user_id=alice.id, plan_name="Alice Plan", source_directories=json.dumps([str(src_dir)]))
    db_session.add(plan)
    db_session.commit()

    storage = get_storage_provider()
    execute_backup_plan(plan.id, alice.id, db_session, storage)
    alice_snap = db_session.query(Snapshot).filter(Snapshot.user_id == alice.id).first()
    alice_sf = alice_snap.files[0]

    # Bob attempts to restore Alice's file
    dest_dir = tmp_path / "bob_restore"
    dest_dir.mkdir()
    with pytest.raises(PermissionError):
        restore_file_by_id(alice_sf.id, str(dest_dir), "keep_both", db_session, storage, user_id=bob.id)

    # Bob queries Command Center: should report 0 recovery points
    bob_telemetry = get_dr_command_center_telemetry(bob.id, db_session)
    assert bob_telemetry["recovery_points"]["total"] == 0
    assert bob_telemetry["recovery_points"]["latest_snapshot"] is None
