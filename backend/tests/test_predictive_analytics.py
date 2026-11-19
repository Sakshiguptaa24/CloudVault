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


def test_storage_forecast_multisnap_regression(db_session):
    user = User(email="regression_user@university.edu", password_hash="hash", full_name="Regression User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Regression Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    now = datetime.utcnow()
    # Add 5 snapshots with steady growth
    for i in range(5):
        s = Snapshot(
            plan_id=plan.id,
            user_id=user.id,
            snapshot_number=i + 1,
            name=f"Snap #{i + 1}",
            total_stored_bytes=1000000 + (i * 200000),
            created_at=now - timedelta(days=(4 - i) * 2)
        )
        db_session.add(s)
    db_session.commit()

    res = storage_forecast(days=30, current_user=user, db=db_session)
    assert res["status"] == "calculated"
    assert res["growth_model"] == "least_squares_linear_regression"
    assert res["forecast_confidence"] == "HIGH"
    assert "projections" in res
    assert res["projections"]["day_7_bytes"] >= res["current_stored_bytes"]
    assert res["projections"]["day_30_bytes"] >= res["projections"]["day_7_bytes"]
    assert res["projections"]["day_90_bytes"] >= res["projections"]["day_30_bytes"]


def test_backup_failure_trends_and_root_causes(db_session):
    from backend.app.services.analytics_service import get_backup_failure_trends

    user = User(email="failure_trends_user@university.edu", password_hash="hash", full_name="Failure User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Failed Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    now = datetime.utcnow()
    # 2 success, 3 failed with different root causes
    j1 = BackupJob(plan_id=plan.id, user_id=user.id, status="SUCCESS", started_at=now - timedelta(days=5))
    j2 = BackupJob(plan_id=plan.id, user_id=user.id, status="SUCCESS", started_at=now - timedelta(days=4))
    j3 = BackupJob(
        plan_id=plan.id,
        user_id=user.id,
        status="FAILED",
        error_message="Permission denied: [Errno 13] Cannot access /var/data",
        started_at=now - timedelta(days=3)
    )
    j4 = BackupJob(
        plan_id=plan.id,
        user_id=user.id,
        status="FAILED",
        error_message="Connection timed out while uploading chunk to storage",
        started_at=now - timedelta(days=2)
    )
    j5 = BackupJob(
        plan_id=plan.id,
        user_id=user.id,
        status="FAILED",
        error_message="SHA256 checksum mismatch integrity check failed",
        started_at=now - timedelta(days=1)
    )
    db_session.add_all([j1, j2, j3, j4, j5])
    db_session.commit()

    trends = get_backup_failure_trends(user_id=user.id, db=db_session, lookback_days=14)
    assert trends["status"] == "success"
    assert trends["total_jobs"] == 5
    assert trends["successful_jobs"] == 2
    assert trends["failed_jobs"] == 3
    assert trends["success_rate_percentage"] == 40.0
    assert trends["failure_rate_percentage"] == 60.0

    assert trends["root_cause_counts"]["PERMISSION_DENIED"] == 1
    assert trends["root_cause_counts"]["TIMEOUT_OR_NETWORK"] == 1
    assert trends["root_cause_counts"]["INTEGRITY_CHECK_FAILED"] == 1

    assert len(trends["root_cause_analysis"]) == 3
    top_cause = trends["root_cause_analysis"][0]
    assert "remediation" in top_cause
    assert len(top_cause["remediation"]) > 10


def test_storage_optimization_suggestions(db_session):
    from backend.app.services.analytics_service import get_storage_optimization_suggestions

    user = User(email="opt_user@university.edu", password_hash="hash", full_name="Optimization User")
    db_session.add(user)
    db_session.commit()

    # Plan with no snapshot
    plan = BackupPlan(user_id=user.id, plan_name="Empty Plan", source_directories="[]", is_active=True)
    db_session.add(plan)
    db_session.commit()

    res = get_storage_optimization_suggestions(user_id=user.id, db=db_session)
    assert res["status"] == "success"
    assert res["total_suggestions"] >= 2
    titles = [s["title"] for s in res["suggestions"]]
    assert any("Empty Plan" in t for t in titles)
    assert any("Cadence" in t for t in titles)



def test_storage_limit_and_quota_exhaustion_prediction(db_session):
    user = User(email="quota_user@university.edu", password_hash="hash", full_name="Quota User", quota_bytes=5000000) # 5 MB quota
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Quota Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    now = datetime.utcnow()
    # 2 snapshots: 1MB on day 0, 2MB on day 1 -> 1MB/day growth
    s1 = Snapshot(plan_id=plan.id, user_id=user.id, snapshot_number=1, name="S1", total_stored_bytes=1000000, created_at=now - timedelta(days=1))
    s2 = Snapshot(plan_id=plan.id, user_id=user.id, snapshot_number=2, name="S2", total_stored_bytes=2000000, created_at=now)
    db_session.add_all([s1, s2])
    db_session.commit()

    res = storage_forecast(days=30, current_user=user, db=db_session)
    assert res["status"] == "calculated"
    assert res["quota_bytes"] == 5000000
    assert res["current_stored_bytes"] == 2000000
    assert res["daily_growth_bytes"] > 0
    # Remaining quota = 3MB, daily growth ~1MB -> ~3 days to quota
    assert res["days_to_quota"] is not None
    assert 2 <= res["days_to_quota"] <= 4


def test_health_score_with_drill_and_worm_and_alert_impact(db_session):
    from backend.app.models import DRDrill

    user = User(email="scoring_user@university.edu", password_hash="hash", full_name="Scoring User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Scoring Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    # Fresh snapshot (<1 hour ago) with WORM lock enabled
    snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Locked Fresh Snap",
        created_at=datetime.utcnow() - timedelta(minutes=30),
        total_stored_bytes=1000,
        total_uncompressed_bytes=2000,
        is_locked=True,
        is_immutable=True
    )
    db_session.add(snap)
    db_session.commit()

    # Add a PASSED DR drill
    drill = DRDrill(
        user_id=user.id,
        snapshot_id=snap.id,
        files_tested=10,
        bytes_tested=2000,
        duration_seconds=1.2,
        restoration_speed_mbps=15.0,
        rpo_hours=0.5,
        estimated_rto_minutes=1.0,
        status="PASSED"
    )
    db_session.add(drill)
    db_session.commit()

    score_clean = calculate_backup_health_score(user.id, db_session)
    assert score_clean["score"] >= 85
    assert score_clean["status"] == "EXCELLENT"
    assert score_clean["breakdown"]["drill_integrity_score"] == 10
    assert score_clean["breakdown"]["retention_protection_score"] == 5
    assert score_clean["breakdown"]["rpo_score"] == 35

    # Trigger active ransomware alert -> score must decrease
    alert = RansomwareAlert(
        user_id=user.id,
        plan_id=plan.id,
        risk_score=85,
        alert_level="CRITICAL",
        status="ACTIVE",
        details='["Suspicious encryption burst"]'
    )
    db_session.add(alert)
    db_session.commit()

    score_alert = calculate_backup_health_score(user.id, db_session)
    assert score_alert["score"] < score_clean["score"]
    assert score_alert["breakdown"]["security_posture_score"] < 15
    assert any("ransomware alert" in r.lower() for r in score_alert["recommendations"])


def test_weekly_report_generation_and_accuracy(db_session):
    from backend.app.services.analytics_service import generate_weekly_report

    user = User(email="report_user@university.edu", password_hash="hash", full_name="Report User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Weekly Plan", source_directories="[]", is_active=True)
    db_session.add(plan)
    db_session.commit()

    now = datetime.utcnow()
    # Add snapshots
    snap1 = Snapshot(plan_id=plan.id, user_id=user.id, snapshot_number=1, name="S1", total_stored_bytes=1000000, created_at=now - timedelta(days=3))
    snap2 = Snapshot(plan_id=plan.id, user_id=user.id, snapshot_number=2, name="S2", total_stored_bytes=1500000, created_at=now - timedelta(days=1))
    db_session.add_all([snap1, snap2])

    # Add jobs
    j1 = BackupJob(plan_id=plan.id, user_id=user.id, status="SUCCESS", started_at=now - timedelta(days=3))
    j2 = BackupJob(plan_id=plan.id, user_id=user.id, status="SUCCESS", started_at=now - timedelta(days=1))
    db_session.add_all([j1, j2])
    db_session.commit()

    report = generate_weekly_report(user.id, db_session)
    assert report["status"] == "success"
    assert report["user_email"] == "report_user@university.edu"
    assert report["backup_activity"]["total_jobs_7d"] == 2
    assert report["backup_activity"]["success_rate_7d"] == 100.0
    assert report["storage_changes"]["physical_stored_bytes"] >= 0
    assert "markdown_report" in report
    assert "CloudVault Weekly Executive Backup & Health Report" in report["markdown_report"]
    assert "report_user@university.edu" in report["markdown_report"]
    assert len(report["prioritized_actions"]) > 0


def test_folder_cadence_recommendations(db_session, tmp_path):
    from backend.app.services.analytics_service import get_folder_cadence_recommendations

    user = User(email="cadence_user@university.edu", password_hash="hash", full_name="Cadence User")
    db_session.add(user)
    db_session.commit()

    # Create dummy folder with a few files
    d = tmp_path / "work_docs"
    d.mkdir()
    for i in range(8):
        (d / f"doc_{i}.txt").write_text("Hello CloudVault")

    import json
    plan = BackupPlan(
        user_id=user.id,
        plan_name="Docs Plan",
        source_directories=json.dumps([str(d)]),
        is_active=True,
        schedule_type="manual"
    )
    db_session.add(plan)
    db_session.commit()

    cadence_res = get_folder_cadence_recommendations(user.id, db_session)
    assert cadence_res["status"] == "success"
    assert cadence_res["total_directories_analyzed"] == 1
    folder_rec = cadence_res["folder_recommendations"][0]
    assert folder_rec["directory_path"] == str(d)
    assert folder_rec["files_count"] == 8
    assert "recommended_schedule" in folder_rec


def test_predictive_analytics_tenant_isolation(db_session):
    from backend.app.services.analytics_service import generate_weekly_report

    user_a = User(email="user_a@university.edu", password_hash="hash", full_name="User A")
    user_b = User(email="user_b@university.edu", password_hash="hash", full_name="User B")
    db_session.add_all([user_a, user_b])
    db_session.commit()

    plan_a = BackupPlan(user_id=user_a.id, plan_name="Plan A", source_directories="[]", is_active=True)
    plan_b = BackupPlan(user_id=user_b.id, plan_name="Plan B", source_directories="[]", is_active=True)
    db_session.add_all([plan_a, plan_b])
    db_session.commit()

    snap_a = Snapshot(plan_id=plan_a.id, user_id=user_a.id, snapshot_number=1, name="Snap A", total_stored_bytes=9999999)
    snap_b = Snapshot(plan_id=plan_b.id, user_id=user_b.id, snapshot_number=1, name="Snap B", total_stored_bytes=111)
    db_session.add_all([snap_a, snap_b])
    db_session.commit()

    overview_a = analytics_overview(current_user=user_a, db=db_session)
    overview_b = analytics_overview(current_user=user_b, db=db_session)

    # Isolated metrics
    report_a = generate_weekly_report(user_a.id, db_session)
    report_b = generate_weekly_report(user_b.id, db_session)

    assert report_a["user_email"] == "user_a@university.edu"
    assert report_b["user_email"] == "user_b@university.edu"
    assert "user_a@university.edu" not in report_b["markdown_report"]


def test_ai_assistant_predictive_queries(db_session):
    from backend.app.routers.ai import query_ai_assistant, AIQueryRequest

    user = User(email="ai_predictive_user@university.edu", password_hash="hash", full_name="AI Predictive User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="AI Test Plan", source_directories="[]", is_active=True)
    db_session.add(plan)
    db_session.commit()

    snap = Snapshot(plan_id=plan.id, user_id=user.id, snapshot_number=1, name="Snap 1", total_stored_bytes=500000, total_uncompressed_bytes=1000000)
    db_session.add(snap)
    db_session.commit()

    prompts = [
        "How healthy is my backup system?",
        "What is likely to happen to my storage over the next month?",
        "Which folders need more frequent backups?",
        "What should I fix first?",
        "How has my storage usage changed?",
        "What security risks should I address?",
        "Generate my weekly report"
    ]

    for p in prompts:
        req = AIQueryRequest(prompt=p)
        res = query_ai_assistant(req, current_user=user, db=db_session)
        assert res is not None
        assert "response" in res
        assert len(res["response"]) > 20
        # Verify no fabricated values
        assert "CloudVault" in res["response"] or "Storage" in res["response"] or "Report" in res["response"] or "Assessment" in res["response"]
