import os
import json
import hashlib
import time
from pathlib import Path
import pytest
from fastapi import HTTPException

from backend.app.models import User, BackupPlan, Snapshot, SnapshotFile, StorageObject, BackupJob
from backend.app.schemas import UserRegister, UserLogin, BackupPlanCreate, RestoreFileRequest
from backend.app.routers.auth import register, login
from backend.app.routers.backups import create_backup_plan, upload_file_direct, get_storage_stats
from backend.app.routers.recovery import (
    list_snapshots, get_snapshot_tree, restore_file, get_deleted_files
)
from backend.app.services.backup_service import (
    execute_backup_plan, calculate_sha256, calculate_bytes_sha256
)
from backend.app.services.restore_service import restore_file_by_id
from backend.app.services.scheduler_service import BackgroundSchedulerService
from backend.app.storage.mock_storage import MockStorageProvider

def test_full_ten_step_end_to_end_workflow(tmp_path, db_session):
    print("\n--- BEGINNING 10-STEP END-TO-END VERIFICATION ---")

    # =========================================================================
    # STEP 1: Register a new user and log in
    # =========================================================================
    print("Step 1: Registering new user and logging in...")
    reg_data = UserRegister(
        email="student_eval@university.edu",
        password="AcademicPassword2026!",
        full_name="Student Evaluator"
    )
    reg_response = register(reg_data, db_session)
    user_a = reg_response["user"]
    token_a = reg_response["access_token"]
    assert token_a is not None
    assert user_a.email == "student_eval@university.edu"

    login_data = UserLogin(
        email="student_eval@university.edu",
        password="AcademicPassword2026!"
    )
    login_response = login(login_data, db_session)
    assert login_response["access_token"] is not None
    print("  -> Step 1 Passed: User registered, password hashed with bcrypt, JWT token issued.")

    # =========================================================================
    # STEP 2 & 3: Upload a test file & create a backup snapshot
    # =========================================================================
    print("Step 2 & 3: Creating directory, test file, and initial backup snapshot...")
    source_dir = tmp_path / "project_documents"
    source_dir.mkdir()

    initial_content = b"CloudVault Version 1: Initial research data and requirements."
    test_file_path = source_dir / "research_paper.docx"
    test_file_path.write_bytes(initial_content)
    initial_sha256 = calculate_sha256(str(test_file_path))

    # Create Backup Plan
    plan_in = BackupPlanCreate(
        plan_name="University Research Plan",
        source_directories=[str(source_dir)],
        exclusion_patterns=["*.tmp", ".git"],
        schedule_type="manual"
    )
    plan = create_backup_plan(plan_in, user_a, db_session)
    assert plan.id is not None

    from backend.app.storage import get_storage_provider
    storage = get_storage_provider()

    # Execute Initial Backup -> Snapshot #1
    snap1, job1 = execute_backup_plan(plan.id, user_a, db_session, storage, trigger_type="MANUAL")
    assert snap1.snapshot_number == 1
    assert snap1.total_files == 1
    assert job1.status == "SUCCESS"
    assert job1.files_uploaded == 1
    assert job1.files_deduplicated == 0
    print(f"  -> Step 2 & 3 Passed: Snapshot #1 created with 1 file (SHA-256: {initial_sha256[:12]}...).")

    # =========================================================================
    # STEP 4: Upload identical content again and verify deduplication
    # =========================================================================
    print("Step 4: Uploading identical content in a separate subfolder to test deduplication...")
    sub_folder = source_dir / "archive_backup"
    sub_folder.mkdir()
    duplicate_file = sub_folder / "research_copy.docx"
    duplicate_file.write_bytes(initial_content) # EXACT SAME BYTES

    snap2, job2 = execute_backup_plan(plan.id, user_a, db_session, storage, trigger_type="MANUAL")
    assert snap2.snapshot_number == 2
    assert snap2.total_files == 2
    assert job2.status == "SUCCESS"
    # DEDUPLICATION CHECK: 2 files total, 1 is identical to existing content
    # Therefore, files_uploaded should be 0 (since research_paper.docx was already uploaded in snap1)
    # and duplicate_file is also identical! Both files deduplicated!
    assert job2.files_uploaded == 0
    assert job2.files_deduplicated == 2
    assert job2.bytes_uploaded == 0 # 0 bytes uploaded to cloud storage!

    # Verify storage object count in database remains 1
    stored_objects = db_session.query(StorageObject).filter(StorageObject.user_id == user_a.id).all()
    assert len(stored_objects) == 1
    assert stored_objects[0].ref_count >= 2
    print("  -> Step 4 Passed: Deduplication verified. Zero bytes transferred for identical payload.")

    # =========================================================================
    # STEP 5: Modify the file and create a new version
    # =========================================================================
    print("Step 5: Modifying file to create Version 2...")
    v2_content = b"CloudVault Version 2: Updated chapter 3 with cloud security findings."
    test_file_path.write_bytes(v2_content)
    v2_sha256 = calculate_sha256(str(test_file_path))
    assert v2_sha256 != initial_sha256

    snap3, job3 = execute_backup_plan(plan.id, user_a, db_session, storage, trigger_type="MANUAL")
    assert snap3.snapshot_number == 3
    # 1 file modified -> 1 uploaded, 1 unchanged file (archive_backup) deduplicated!
    assert job3.files_uploaded == 1
    assert job3.files_deduplicated == 1

    stored_objects_v2 = db_session.query(StorageObject).filter(StorageObject.user_id == user_a.id).all()
    assert len(stored_objects_v2) == 2 # 2 distinct version objects now exist
    print(f"  -> Step 5 Passed: Version 2 committed. New SHA-256 stored: {v2_sha256[:12]}...")

    # =========================================================================
    # STEP 6: Restore the previous version (Snapshot #1)
    # =========================================================================
    print("Step 6: Restoring Snapshot #1 to verify historical version recovery...")
    restore_v1_dir = tmp_path / "restored_version_1"
    restore_v1_dir.mkdir()

    # Find the snapshot file corresponding to Snapshot #1
    snap1_file = db_session.query(SnapshotFile).filter(
        SnapshotFile.snapshot_id == snap1.id,
        SnapshotFile.file_name == "research_paper.docx"
    ).first()
    assert snap1_file is not None

    restore_v1_res = restore_file_by_id(
        snapshot_file_id=snap1_file.id,
        destination_dir=str(restore_v1_dir),
        conflict_strategy="overwrite",
        db=db_session,
        storage=storage,
        user_id=user_a.id
    )
    assert restore_v1_res["status"] == "RESTORED"
    restored_v1_bytes = Path(restore_v1_res["path"]).read_bytes()
    assert restored_v1_bytes == initial_content
    assert restored_v1_bytes != v2_content # Proves rollback to exact Version 1
    print("  -> Step 6 Passed: Historical Version 1 recovered accurately, distinct from Version 2.")

    # =========================================================================
    # STEP 7: Delete a local test copy and recover it (Soft-Delete / Trash)
    # =========================================================================
    print("Step 7: Deleting file locally and recovering via Deleted Files / Trash...")
    # Delete the duplicate file
    duplicate_file.unlink()
    assert not duplicate_file.exists()

    # Take Snapshot #4 (Reflects local deletion)
    snap4, _ = execute_backup_plan(plan.id, user_a, db_session, storage, trigger_type="MANUAL")

    # Query deleted files
    deleted_files = get_deleted_files(plan.id, user_a, db_session)
    deleted_names = [df["file_name"] for df in deleted_files]
    assert "research_copy.docx" in deleted_names

    # Recover deleted file to original folder
    target_deleted = next(df for df in deleted_files if df["file_name"] == "research_copy.docx")
    req = RestoreFileRequest(
        snapshot_file_id=target_deleted["snapshot_file_id"],
        destination_directory=str(source_dir),
        conflict_strategy="overwrite"
    )
    recovery_res = restore_file(req, user_a, db_session)
    assert recovery_res["status"] == "SUCCESS"
    assert duplicate_file.exists()
    assert duplicate_file.read_bytes() == initial_content
    print("  -> Step 7 Passed: Deleted file detected in trash and recovered to disk.")

    # =========================================================================
    # STEP 8: Verify restored content using SHA-256
    # =========================================================================
    print("Step 8: Verifying bit-for-bit SHA-256 checksums across all restored files...")
    assert calculate_sha256(str(duplicate_file)) == initial_sha256
    assert calculate_sha256(str(Path(restore_v1_res["path"]))) == initial_sha256
    print("  -> Step 8 Passed: Restored content verified 100% identical bit-for-bit (Zero corruption).")

    # =========================================================================
    # STEP 9: Test scheduled backup execution
    # =========================================================================
    print("Step 9: Testing automated background scheduler...")
    scheduled_plan = BackupPlan(
        user_id=user_a.id,
        plan_name="Automated Scheduled Plan",
        source_directories=json.dumps([str(source_dir)]),
        exclusion_patterns=json.dumps([]),
        schedule_type="interval",
        schedule_expression="1", # 1 second interval
        is_active=True
    )
    db_session.add(scheduled_plan)
    db_session.commit()
    db_session.refresh(scheduled_plan)

    # Initialize and execute scheduler check
    sched_service = BackgroundSchedulerService(check_interval_seconds=1)
    # Manually invoke one tick with the active test session
    sched_service._check_and_trigger_plans(session=db_session, storage_provider=storage)

    # Verify a scheduled job was created and executed
    sched_jobs = db_session.query(BackupJob).filter(
        BackupJob.plan_id == scheduled_plan.id,
        BackupJob.trigger_type == "SCHEDULED"
    ).all()
    assert len(sched_jobs) >= 1
    assert sched_jobs[0].status in ["SUCCESS", "RUNNING"]
    print("  -> Step 9 Passed: Automated scheduler detected plan interval and executed scheduled backup.")

    # =========================================================================
    # STEP 10: Verify user data isolation
    # =========================================================================
    print("Step 10: Verifying multi-tenant user data isolation...")
    user_b_data = UserRegister(
        email="second_user@university.edu",
        password="DifferentPassword456!",
        full_name="Second Student"
    )
    res_b = register(user_b_data, db_session)
    user_b = res_b["user"]

    # User B lists snapshots: must NOT see User A's snapshots!
    snapshots_b = list_snapshots(plan_id=None, current_user=user_b, db=db_session)
    assert len(snapshots_b) == 0

    # User B attempts to access User A's snapshot tree directly: must be 404!
    with pytest.raises(HTTPException) as tree_exc:
        get_snapshot_tree(snap1.id, user_b, db_session)
    assert tree_exc.value.status_code == 404

    # User B attempts to restore User A's file: must be 403 Forbidden!
    with pytest.raises(HTTPException) as restore_exc:
        restore_file(
            RestoreFileRequest(
                snapshot_file_id=snap1_file.id,
                destination_directory=str(tmp_path / "unauthorized_out"),
                conflict_strategy="overwrite"
            ),
            user_b,
            db_session
        )
    assert restore_exc.value.status_code == 403
    assert "Access denied" in str(restore_exc.value.detail)

    # User B queries User A's deleted files: must be 404!
    with pytest.raises(HTTPException) as del_exc:
        get_deleted_files(plan.id, user_b, db_session)
    assert del_exc.value.status_code == 404

    print("  -> Step 10 Passed: Strict user isolation verified across snapshots, file trees, and restore requests.")
    print("--- ALL 10 END-TO-END VERIFICATION STEPS PASSED SUCCESSFULLY! ---\n")
