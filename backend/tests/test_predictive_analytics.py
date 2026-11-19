import json
from datetime import datetime, timedelta
from backend.app.models import User, BackupPlan, Snapshot, SnapshotFile, StorageObject, BackupJob, RansomwareAlert
from backend.app.services.analytics_service import (
    get_analytics_overview, get_storage_forecast, get_top_large_files, calculate_backup_health_score
)
from backend.app.routers.analytics import (
    analytics_overview, storage_forecast, backup_health_score, list_large_files
)

def test_analytics_overview(db_session):
    user = User(email="analytics_user@university.edu", password_hash="hash", full_name="Analytics User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Core Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Snapshot 1",
        total_files=2,
        total_uncompressed_bytes=2000000,
        total_stored_bytes=1000000
    )
    db_session.add(snap)
    db_session.commit()

    # Create dummy storage object
    so = StorageObject(
        user_id=user.id,
        sha256_hash="abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef567890",
        original_size=2000000,
        compressed_size=1000000,
        storage_path="mock/abcd"
    )
    db_session.add(so)
    db_session.commit()

    # Create dummy files
    sf1 = SnapshotFile(
        snapshot_id=snap.id,
        storage_object_id=so.id,
        relative_path="docs/paper.pdf",
        file_name="paper.pdf",
        file_extension=".pdf",
        file_size=1500000,
        modified_at=datetime.utcnow()
    )
    sf2 = SnapshotFile(
        snapshot_id=snap.id,
        storage_object_id=so.id,
        relative_path="src/main.py",
        file_name="main.py",
        file_extension=".py",
        file_size=500000,
        modified_at=datetime.utcnow()
    )
    db_session.add_all([sf1, sf2])
    db_session.commit()

    overview = analytics_overview(current_user=user, db=db_session)
    assert overview["status"] == "success"
    assert overview["physical_stored_bytes"] == 1000000
    assert overview["logical_uncompressed_bytes"] == 2000000
    assert overview["bytes_saved"] == 1000000
    assert overview["deduplication_ratio"] == 2.0
    assert len(overview["file_types_breakdown"]) >= 2
    assert "gcs_standard" in overview["estimated_cost_usd_monthly"]

def test_storage_forecast_baseline_and_growth(db_session):
    user = User(email="forecast_user@university.edu", password_hash="hash", full_name="Forecast User")
    db_session.add(user)
    db_session.commit()

    # Baseline with 0 snapshots
    res_base = storage_forecast(days=30, current_user=user, db=db_session)
    assert res_base["status"] == "baseline_estimate"

    # Add 2 snapshots spaced over time
    plan = BackupPlan(user_id=user.id, plan_name="Growth Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    snap1 = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Snap 1",
        total_stored_bytes=1000000,
        created_at=datetime.utcnow() - timedelta(days=5)
    )
    snap2 = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=2,
        name="Snap 2",
        total_stored_bytes=2000000,
        created_at=datetime.utcnow()
    )
    db_session.add_all([snap1, snap2])
    db_session.commit()

    res_growth = storage_forecast(days=30, current_user=user, db=db_session)
    assert res_growth["status"] == "calculated"
    assert res_growth["daily_growth_bytes"] > 0
    assert res_growth["projected_bytes_30d"] > res_growth["current_stored_bytes"]

def test_backup_health_score(db_session):
    user = User(email="health_user@university.edu", password_hash="hash", full_name="Health User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Healthy Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    # Recent snapshot (within 1 hour)
    snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Fresh Snap",
        created_at=datetime.utcnow() - timedelta(hours=1),
        total_stored_bytes=500,
        total_uncompressed_bytes=1000
    )
    db_session.add(snap)
    db_session.commit()

    score_res = backup_health_score(current_user=user, db=db_session)
    assert score_res["score"] >= 70
    assert score_res["status"] in ["EXCELLENT", "HEALTHY"]
    assert score_res["components"]["rpo_recency_score"] == 35
