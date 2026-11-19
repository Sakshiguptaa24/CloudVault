from fastapi import APIRouter, Depends
from backend.app.auth import get_current_user
from backend.app.models import User
from backend.app.services.scheduler_service import scheduler

router = APIRouter(prefix="/api/v1/scheduler", tags=["Scheduler"])

@router.get("/status")
def get_scheduler_status(current_user: User = Depends(get_current_user)):
    return {
        "running": scheduler._running,
        "check_interval_seconds": scheduler.check_interval,
        "active_monitored_plans": len(scheduler._last_run)
    }

@router.post("/start")
def start_scheduler(current_user: User = Depends(get_current_user)):
    scheduler.start()
    return {"status": "SUCCESS", "message": "Background backup scheduler started"}

@router.post("/stop")
def stop_scheduler(current_user: User = Depends(get_current_user)):
    scheduler.stop()
    return {"status": "SUCCESS", "message": "Background backup scheduler stopped"}

