import pytest
import zlib
import gzip
from datetime import datetime, timedelta
from backend.app.models import User, BackupPlan, Snapshot, SnapshotFile, StorageObject, DRDrill
from backend.app.services.restore_service import calculate_bytes_sha256
from backend.app.services.dr_service import get_dr_metrics, run_synthetic_recovery_drill
from backend.app.routers.dr import dr_metrics, simulate_recovery_drill, dr_history, dr_readiness, SimulateDrillRequest
from backend.app.storage import get_storage_provider

def test_dr_metrics_calculation(db_session):
    user = User(email="dr_user@university.edu", password_hash="hash", full_name="DR User")
    db_session.add(user)
    db_session.commit()

    # Initial state: no snapshots
    metrics = dr_metrics(current_user=user, db=db_session)
    assert metrics["rpo"]["status"] == "NO_BACKUPS"
    assert metrics["readiness_score"] < 70

    plan = BackupPlan(user_id=user.id, plan_name="DR Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    # Create a snapshot from 4 hours ago
    four_hours_ago = datetime.utcnow() - timedelta(hours=4)
    snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Hourly Snapshot",
        total_files=2,
        total_uncompressed_bytes=2048,
        total_stored_bytes=1024,
        created_at=four_hours_ago
    )
    db_session.add(snap)
    db_session.commit()

    metrics = dr_metrics(current_user=user, db=db_session)
    assert metrics["rpo"]["status"] == "HEALTHY"
    assert metrics["rpo"]["hours"] is not None
    assert 3.8 <= metrics["rpo"]["hours"] <= 4.2
    assert metrics["readiness_score"] >= 70

    # Test readiness badge endpoint
    badge = dr_readiness(current_user=user, db=db_session)
    assert badge["rpo_status"] == "HEALTHY"
    assert badge["readiness_score"] >= 70

def test_synthetic_recovery_drill_success(db_session):
    storage = get_storage_provider()
    user = User(email="dr_drill_user@university.edu", password_hash="hash", full_name="Drill User")
    db_session.add(user)
    db_session.commit()

    # Store a test object in storage
    content = b"CRITICAL DATABASE PAYLOAD FOR DISASTER RECOVERY TEST"
    content_hash = calculate_bytes_sha256(content)
    compressed = gzip.compress(content)
    storage_path = f"users/{user.id}/blocks/{content_hash}.dat"
    storage.upload_bytes(compressed, storage_path)

    so = StorageObject(
        user_id=user.id,
        sha256_hash=content_hash,
        original_size=len(content),
        compressed_size=len(compressed),
        storage_path=storage_path,
        storage_class="STANDARD",
        compression_algo="gzip"
    )
    db_session.add(so)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Prod Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Production Snapshot",
        total_files=1,
        total_uncompressed_bytes=len(content),
        total_stored_bytes=len(compressed),
        verification_status="UNVERIFIED"
    )
    db_session.add(snap)
    db_session.commit()

    sf = SnapshotFile(
        snapshot_id=snap.id,
        storage_object_id=so.id,
        relative_path="production.db",
        file_name="production.db",
        file_extension=".db",
        file_size=len(content),
        modified_at=datetime.utcnow()
    )
    db_session.add(sf)
    db_session.commit()

    # Trigger synthetic drill via router
    req = SimulateDrillRequest(snapshot_id=snap.id)
    drill_result = simulate_recovery_drill(req, current_user=user, db=db_session)

    assert drill_result["status"] == "PASSED"
    assert drill_result["files_tested"] == 1
    assert drill_result["bytes_tested"] == len(content)
    assert drill_result["restoration_speed_mbps"] > 0
    assert drill_result["error_details"] is None

    # Check snapshot verification status updated
    db_session.refresh(snap)
    assert snap.verification_status == "VERIFIED"
    assert snap.verified_at is not None

def test_synthetic_recovery_drill_corruption_detection(db_session):
    storage = get_storage_provider()
    user = User(email="corrupt_drill_user@university.edu", password_hash="hash", full_name="Corrupt User")
    db_session.add(user)
    db_session.commit()

    # Store a corrupted object (stored content does not match recorded SHA-256)
    content = b"LEGIT CONTENT"
    fake_hash = "0" * 64
    compressed = gzip.compress(content)
    storage_path = f"users/{user.id}/blocks/corrupt_test.dat"
    storage.upload_bytes(compressed, storage_path)

    so = StorageObject(
        user_id=user.id,
        sha256_hash=fake_hash,  # Purposely mismatched
        original_size=len(content),
        compressed_size=len(compressed),
        storage_path=storage_path,
        storage_class="STANDARD",
        compression_algo="gzip"
    )
    db_session.add(so)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Corrupt Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Corrupted Snapshot",
        total_files=1,
        total_uncompressed_bytes=len(content),
        total_stored_bytes=len(compressed),
        verification_status="UNVERIFIED"
    )
    db_session.add(snap)
    db_session.commit()

    sf = SnapshotFile(
        snapshot_id=snap.id,
        storage_object_id=so.id,
        relative_path="corrupted.bin",
        file_name="corrupted.bin",
        file_extension=".bin",
        file_size=len(content),
        modified_at=datetime.utcnow()
    )
    db_session.add(sf)
    db_session.commit()

    req = SimulateDrillRequest(snapshot_id=snap.id)
    drill_result = simulate_recovery_drill(req, current_user=user, db=db_session)

    assert drill_result["status"] == "FAILED"
    assert "SHA-256 integrity mismatch" in drill_result["error_details"]

    db_session.refresh(snap)
    assert snap.verification_status == "FAILED"

def test_dr_history_endpoint(db_session):
    user = User(email="dr_history_user@university.edu", password_hash="hash", full_name="History User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="History Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="History Snapshot",
        total_files=1,
        total_uncompressed_bytes=100,
        total_stored_bytes=50
    )
    db_session.add(snap)
    db_session.commit()

    drill = DRDrill(
        user_id=user.id,
        snapshot_id=snap.id,
        files_tested=1,
        bytes_tested=100,
        duration_seconds=0.1,
        restoration_speed_mbps=1.0,
        rpo_hours=2.0,
        estimated_rto_minutes=0.5,
        status="PASSED"
    )
    db_session.add(drill)
    db_session.commit()

    history = dr_history(limit=10, current_user=user, db=db_session)
    assert "drills" in history
    assert history["count"] == 1
    assert history["drills"][0]["drill_id"] == drill.id
    assert history["drills"][0]["status"] == "PASSED"
