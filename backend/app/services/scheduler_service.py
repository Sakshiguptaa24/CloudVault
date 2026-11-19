import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, Any
from backend.app.database import SessionLocal
from backend.app.models import BackupPlan, User
from backend.app.storage import get_storage_provider
from backend.app.services.backup_service import execute_backup_plan

logger = logging.getLogger("cloudvault.scheduler")

class BackgroundSchedulerService:
    """Lightweight background scheduler daemon for automated backups."""

    def __init__(self, check_interval_seconds: int = 15):
        self.check_interval = check_interval_seconds
        self._running = False
        self._thread = None
        self._plan_locks = set()
        self._last_run: Dict[str, datetime] = {}

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="CloudVaultScheduler")
        self._thread.start()
        logger.info("CloudVault Background Scheduler started.")

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        logger.info("CloudVault Background Scheduler stopped.")

    def _run_loop(self):
        while self._running:
            try:
                self._check_and_trigger_plans()
            except Exception as e:
                logger.error(f"Error in scheduler tick: {e}")
            time.sleep(self.check_interval)

    def _check_and_trigger_plans(self, session=None, storage_provider=None):
        owns_session = session is None
        db = session if session else SessionLocal()
        try:
            active_plans = db.query(BackupPlan).filter(
                BackupPlan.is_active == True,
                BackupPlan.schedule_type != "manual"
            ).all()

            now = datetime.utcnow()

            for plan in active_plans:
                if plan.id in self._plan_locks:
                    continue

                should_run = False
                last_time = self._last_run.get(plan.id)

                if plan.schedule_type == "interval":
                    try:
                        interval_sec = int(plan.schedule_expression)
                    except ValueError:
                        interval_sec = 3600

                    if not last_time or (now - last_time) >= timedelta(seconds=interval_sec):
                        should_run = True

                elif plan.schedule_type == "daily":
                    # Expression like "02:00"
                    target_time = plan.schedule_expression.strip()
                    current_time_str = now.strftime("%H:%M")
                    if current_time_str == target_time:
                        if not last_time or (now.date() > last_time.date()):
                            should_run = True

                if should_run:
                    self._plan_locks.add(plan.id)
                    user = db.query(User).filter(User.id == plan.user_id).first()
                    if user:
                        if owns_session:
                            threading.Thread(
                                target=self._execute_scheduled_job,
                                args=(plan.id, user.id),
                                daemon=True
                            ).start()
                        else:
                            # Synchronous execution for test contexts
                            self._execute_scheduled_job(plan.id, user.id, session=db, storage_provider=storage_provider)
        finally:
            if owns_session:
                db.close()

    def _execute_scheduled_job(self, plan_id: str, user_id: str, session=None, storage_provider=None):
        owns_session = session is None
        db = session if session else SessionLocal()
        storage = storage_provider or get_storage_provider()
        try:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return
            logger.info(f"Triggering scheduled backup for plan: {plan_id}")
            execute_backup_plan(plan_id, user, db, storage, trigger_type="SCHEDULED")
            self._last_run[plan_id] = datetime.utcnow()
        except Exception as e:
            logger.error(f"Scheduled backup failed for plan {plan_id}: {e}")
        finally:
            self._plan_locks.discard(plan_id)
            if owns_session:
                db.close()

scheduler = BackgroundSchedulerService()

