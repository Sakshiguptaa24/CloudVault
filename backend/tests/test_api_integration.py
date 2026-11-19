import io
from fastapi import UploadFile
from backend.app.schemas import BackupPlanCreate
from backend.app.routers.backups import (
    create_backup_plan, list_backup_plans, upload_file_direct,
    get_backup_jobs, get_storage_stats
)
from backend.app.routers.recovery import list_snapshots, get_snapshot_tree

def test_api_backup_flow(db_session):
    # Setup test user
    from backend.app.models import User
    user = User(
        email="api_user@university.edu",
        password_hash="fakehash",
        full_name="API User"
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # 1. Create Backup Plan
    plan_in = BackupPlanCreate(
        plan_name="Daily Academic Backups",
        source_directories=["./sample_docs"],
        schedule_type="interval",
        schedule_expression="7200"
    )
    plan = create_backup_plan(plan_in, user, db_session)
    assert plan.plan_name == "Daily Academic Backups"
    assert plan.id is not None

    # 2. List Plans
    plans = list_backup_plans(user, db_session)
    assert len(plans) == 1

    # 3. Direct File Upload (Upload 1)
    file_content = b"Content of presentation slide 1"
    upload_file1 = UploadFile(
        filename="slide1.txt",
        file=io.BytesIO(file_content)
    )
    res1 = upload_file_direct(plan.id, "slide1.txt", upload_file1, user, db_session)
    assert res1["status"] == "SUCCESS"
    assert res1["deduplicated"] is False
    assert res1["bytes_stored"] > 0

    # 4. Direct File Upload (Upload 2 with identical content -> Deduplicated!)
    upload_file2 = UploadFile(
        filename="slide1_copy.txt",
        file=io.BytesIO(file_content)
    )
    res2 = upload_file_direct(plan.id, "slide1_copy.txt", upload_file2, user, db_session)
    assert res2["status"] == "SUCCESS"
    assert res2["deduplicated"] is True
    assert res2["bytes_stored"] == 0 # 0 bytes uploaded to cloud/storage!

    # 5. Check Snapshots
    snapshots = list_snapshots(plan.id, user, db_session)
    assert len(snapshots) == 2

    # 6. Check Snapshot Tree
    tree = get_snapshot_tree(snapshots[0].id, user, db_session)
    assert len(tree) == 1

    # 7. Check Jobs History
    jobs = get_backup_jobs(10, user, db_session)
    assert len(jobs) == 2
    assert jobs[0].status == "SUCCESS"

    # 8. Check Storage Stats
    stats = get_storage_stats(user, db_session)
    assert stats["total_snapshots"] == 2
    assert stats["total_files_protected"] == 2
    assert stats["bytes_saved_deduplication"] > 0
    assert stats["savings_percentage"] > 0
