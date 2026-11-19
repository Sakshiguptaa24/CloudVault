import pytest
from datetime import datetime, timedelta
from backend.app.models import User, BackupJob, RansomwareAlert, DRDrill
from backend.app.routers.events import poll_recent_events

def test_events_poll_endpoint(db_session):
    user = User(email="events_user@university.edu", password_hash="hash", full_name="Events User")
    db_session.add(user)
    db_session.commit()

    # Initial poll should return zero
    res = poll_recent_events(since_seconds=60, current_user=user, db=db_session)
    assert res["status"] == "success"
    assert res["running_jobs"] == 0
    assert len(res["new_alerts"]) == 0
    assert len(res["recent_drills"]) == 0

    # Add running backup job
    job = BackupJob(
        user_id=user.id,
        status="RUNNING",
        trigger_type="AI"
    )
    db_session.add(job)
    db_session.commit()

    # Add alert
    alert = RansomwareAlert(
        user_id=user.id,
        alert_level="HIGH_RISK",
        risk_score=85,
        details='{"test": "anomaly"}'
    )
    db_session.add(alert)
    db_session.commit()

    # Poll again
    res = poll_recent_events(since_seconds=60, current_user=user, db=db_session)
    assert res["running_jobs"] == 1
    assert len(res["new_alerts"]) == 1
    assert res["new_alerts"][0]["severity"] == "HIGH_RISK"
    assert res["new_alerts"][0]["score"] == 85
