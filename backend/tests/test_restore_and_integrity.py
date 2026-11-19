import os
import json
import pytest
from pathlib import Path
from backend.app.models import User, BackupPlan, SnapshotFile
from backend.app.services.backup_service import execute_backup_plan, calculate_bytes_sha256
from backend.app.services.restore_service import (
    restore_file_by_id, restore_snapshot, get_deleted_files_for_plan
)
from backend.app.storage.mock_storage import MockStorageProvider

def test_restore_integrity_and_trash_recovery(tmp_path, db_session):
    # 1. Setup User and Source Folder
    user = User(
        email="restore_tester@university.edu",
        password_hash="fakehash",
        full_name="Restore Tester"
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    src_dir = tmp_path / "restore_source"
    src_dir.mkdir()

    original_file1 = src_dir / "report.pdf"
    original_file2 = src_dir / "code.py"

    content1 = b"%PDF-1.4 Critical Research Data and Findings"
    content2 = b"def calculate(): return 42"

    original_file1.write_bytes(content1)
    original_file2.write_bytes(content2)

    plan = BackupPlan(
        user_id=user.id,
        plan_name="Restore Test Plan",
        source_directories=json.dumps([str(src_dir)]),
        exclusion_patterns=json.dumps([]),
        schedule_type="manual"
    )
    db_session.add(plan)
    db_session.commit()
    db_session.refresh(plan)

    storage = MockStorageProvider(base_dir=str(tmp_path / "mock_store"))

    # 2. Take Baseline Backup (Snapshot 1)
    snap1, _ = execute_backup_plan(plan.id, user, db_session, storage)
    assert snap1.total_files == 2

    # 3. Test Granular File Restore with SHA-256 Integrity Verification
    restore_dest = tmp_path / "restored_output"
    snap_file = db_session.query(SnapshotFile).filter(
        SnapshotFile.snapshot_id == snap1.id,
        SnapshotFile.file_name == "report.pdf"
    ).first()
    assert snap_file is not None

    res = restore_file_by_id(snap_file.id, str(restore_dest), "overwrite", db_session, storage)
    assert res["status"] == "RESTORED"
    assert res["sha256_verified"] is True

    restored_path = Path(res["path"])
    assert restored_path.exists()
    assert restored_path.read_bytes() == content1
    assert calculate_bytes_sha256(restored_path.read_bytes()) == calculate_bytes_sha256(content1)

    # 4. Test Conflict Resolution: 'rename' strategy
    res_rename = restore_file_by_id(snap_file.id, str(restore_dest), "rename", db_session, storage)
    assert res_rename["status"] == "RESTORED"
    assert "_restored_" in res_rename["path"]

    # 5. Test Conflict Resolution: 'skip' strategy
    res_skip = restore_file_by_id(snap_file.id, str(restore_dest), "skip", db_session, storage)
    assert res_skip["status"] == "SKIPPED"

    # 6. Test Deleted-File Recovery (Soft-Delete / Trash)
    # Simulate user accidentally deleting code.py
    original_file2.unlink()
    assert not original_file2.exists()

    # Take Snapshot 2 (Incremental backup after deletion)
    snap2, _ = execute_backup_plan(plan.id, user, db_session, storage)
    assert snap2.total_files == 1 # Only report.pdf remains

    # Query Deleted Files API logic
    deleted_files = get_deleted_files_for_plan(plan.id, db_session)
    assert len(deleted_files) == 1
    assert deleted_files[0]["file_name"] == "code.py"
    assert deleted_files[0]["last_seen_snapshot_id"] == snap1.id

    # Restore the deleted file from trash
    undelete_res = restore_file_by_id(
        deleted_files[0]["snapshot_file_id"],
        str(src_dir),
        "overwrite",
        db_session,
        storage
    )
    assert undelete_res["status"] == "RESTORED"
    assert original_file2.exists()
    assert original_file2.read_bytes() == content2

    # 7. Test Silent Corruption Detection
    # Intentionally corrupt the physical stored object
    corrupt_storage_path = snap_file.storage_object.storage_path
    storage.upload_bytes(b"CORRUPTED_BYTES_IN_STORAGE", corrupt_storage_path)

    # Restore must raise an integrity error!
    with pytest.raises(ValueError) as exc_info:
        restore_file_by_id(snap_file.id, str(tmp_path / "corrupted_out"), "overwrite", db_session, storage)
    assert "Integrity check failed" in str(exc_info.value)

