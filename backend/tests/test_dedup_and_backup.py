import os
import json
import pytest
from pathlib import Path
from backend.app.models import User, BackupPlan, Snapshot, StorageObject, BackupJob
from backend.app.services.backup_service import (
    calculate_sha256, scan_directory, execute_backup_plan
)
from backend.app.storage.mock_storage import MockStorageProvider

def test_deduplication_and_incremental_backup(tmp_path, db_session):
    # 1. Create a User
    user = User(
        email="backup_tester@university.edu",
        password_hash="fakehash",
        full_name="Backup Tester"
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # 2. Setup Source Folders with Identical Files (To test Deduplication)
    src_dir = tmp_path / "source_folder"
    src_dir.mkdir()

    sub_dir_a = src_dir / "folder_a"
    sub_dir_b = src_dir / "folder_b"
    sub_dir_a.mkdir()
    sub_dir_b.mkdir()

    content_identical = b"This is a common shared library document."
    content_unique = b"Unique document for folder A only."

    file_a1 = sub_dir_a / "doc1.txt"
    file_b1 = sub_dir_b / "doc1_duplicate.txt"
    file_a2 = sub_dir_a / "unique.txt"

    file_a1.write_bytes(content_identical)
    file_b1.write_bytes(content_identical) # IDENTICAL CONTENT
    file_a2.write_bytes(content_unique)

    # Verify scan finds 3 files
    scanned = scan_directory(str(src_dir))
    assert len(scanned) == 3

    # 3. Create Backup Plan
    plan = BackupPlan(
        user_id=user.id,
        plan_name="Test Dedup Plan",
        source_directories=json.dumps([str(src_dir)]),
        exclusion_patterns=json.dumps(["*.tmp"]),
        schedule_type="manual"
    )
    db_session.add(plan)
    db_session.commit()
    db_session.refresh(plan)

    storage = MockStorageProvider(base_dir=str(tmp_path / "mock_store"))

    # 4. Execute First Backup (Snapshot 1)
    snap1, job1 = execute_backup_plan(plan.id, user, db_session, storage, trigger_type="MANUAL")

    assert snap1.snapshot_number == 1
    assert snap1.total_files == 3
    assert job1.status == "SUCCESS"
    assert job1.files_scanned == 3

    # CRITICAL DEDUPLICATION CHECK:
    # 3 files total, 2 are identical -> exactly 2 physical uploads, 1 deduplicated!
    assert job1.files_uploaded == 2
    assert job1.files_deduplicated == 1
    assert job1.bytes_deduplicated == len(content_identical)

    # Storage objects in database must be 2, not 3
    storage_objs = db_session.query(StorageObject).filter(StorageObject.user_id == user.id).all()
    assert len(storage_objs) == 2

    # The duplicated object must have ref_count == 2
    shared_hash = calculate_sha256(str(file_a1))
    shared_obj = db_session.query(StorageObject).filter(StorageObject.sha256_hash == shared_hash).first()
    assert shared_obj.ref_count == 2

    # 5. Incremental Backup (Snapshot 2) - Modify 1 file, keep others unchanged
    file_a2.write_bytes(b"Modified unique document content!")

    snap2, job2 = execute_backup_plan(plan.id, user, db_session, storage, trigger_type="MANUAL")
    assert snap2.snapshot_number == 2
    assert snap2.snapshot_type == "incremental"
    assert job2.files_scanned == 3
    # In run 2: 1 file modified -> 1 uploaded, 2 deduplicated!
    assert job2.files_uploaded == 1
    assert job2.files_deduplicated == 2

