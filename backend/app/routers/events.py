import asyncio
import json
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.app.database import get_db, SessionLocal
from backend.app.models import User, BackupJob, RansomwareAlert, DRDrill
from backend.app.auth import get_current_user, verify_token

router = APIRouter(prefix="/api/v1/events", tags=["Real-Time Notifications & SSE"])

async def event_generator(user_id: str, request: Request):
    """
    Asynchronous Server-Sent Events generator.
    Yields real-time events for backup progress, ransomware alarms,
    and DR drill completions with keep-alive heartbeat.
    """
    last_check = datetime.utcnow()
    # Send initial connection event
    yield f"data: {json.dumps({'type': 'CONNECTED', 'timestamp': datetime.utcnow().isoformat(), 'message': 'CloudVault real-time event stream active'})}\n\n"

    while True:
        if await request.is_disconnected():
            break

        db: Session = SessionLocal()
        try:
            # 1. Check for running backup jobs
            running_jobs = db.query(BackupJob).filter(
                BackupJob.user_id == user_id,
                BackupJob.status == "RUNNING"
            ).all()

            for job in running_jobs:
                job_data = {
                    "type": "BACKUP_PROGRESS",
                    "job_id": job.id,
                    "status": job.status,
                    "scanned": job.files_scanned,
                    "uploaded": job.files_uploaded,
                    "timestamp": datetime.utcnow().isoformat()
                }
                yield f"data: {json.dumps(job_data)}\n\n"

            # 2. Check for new ransomware alerts
            recent_alerts = db.query(RansomwareAlert).filter(
                RansomwareAlert.user_id == user_id,
                RansomwareAlert.created_at >= last_check
            ).all()

            for alert in recent_alerts:
                alert_data = {
                    "type": "RANSOMWARE_ALERT",
                    "alert_id": alert.id,
                    "severity": alert.alert_level,
                    "risk_score": alert.risk_score,
                    "details": alert.details,
                    "timestamp": alert.created_at.isoformat()
                }
                yield f"data: {json.dumps(alert_data)}\n\n"

            # 3. Check for recent DR drills
            recent_drills = db.query(DRDrill).filter(
                DRDrill.user_id == user_id,
                DRDrill.created_at >= last_check
            ).all()

            for drill in recent_drills:
                drill_data = {
                    "type": "DR_DRILL_RESULT",
                    "drill_id": drill.id,
                    "status": drill.status,
                    "speed_mbps": drill.restoration_speed_mbps,
                    "timestamp": drill.created_at.isoformat()
                }
                yield f"data: {json.dumps(drill_data)}\n\n"

            last_check = datetime.utcnow()

            # Heartbeat ping
            yield f"data: {json.dumps({'type': 'HEARTBEAT', 'timestamp': datetime.utcnow().isoformat()})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'ERROR', 'error': str(e)})}\n\n"
        finally:
            db.close()

        # Poll interval: 3 seconds
        await asyncio.sleep(3)

@router.get("/stream")
def sse_events_stream(
    request: Request,
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    raw_token = token
    if not raw_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            raw_token = auth_header.split(" ", 1)[1].strip()

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required for real-time event stream",
            headers={"WWW-Authenticate": "Bearer"}
        )

    payload = verify_token(raw_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject identity",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or deactivated",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return StreamingResponse(
        event_generator(user.id, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@router.get("/poll")
def poll_recent_events(
    since_seconds: int = Query(30, ge=5, le=300),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Fallback REST polling endpoint for clients where SSE is blocked by proxies."""
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(seconds=since_seconds)

    alerts = db.query(RansomwareAlert).filter(
        RansomwareAlert.user_id == current_user.id,
        RansomwareAlert.created_at >= cutoff
    ).all()

    drills = db.query(DRDrill).filter(
        DRDrill.user_id == current_user.id,
        DRDrill.created_at >= cutoff
    ).all()

    running = db.query(BackupJob).filter(
        BackupJob.user_id == current_user.id,
        BackupJob.status == "RUNNING"
    ).all()

    return {
        "status": "success",
        "running_jobs": len(running),
        "new_alerts": [
            {"id": a.id, "severity": a.alert_level, "score": a.risk_score} for a in alerts
        ],
        "recent_drills": [
            {"id": d.id, "status": d.status, "speed": d.restoration_speed_mbps} for d in drills
        ]
    }
