from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models import User, BackupPlan, Snapshot
from backend.app.auth import get_current_user
from backend.app.storage import get_storage_provider
from backend.app.ai.provider import get_ai_provider
from backend.app.ai.security import validate_and_consume_token, record_audit_log
from backend.app.services.backup_service import execute_backup_plan

router = APIRouter(prefix="/api/v1/ai", tags=["AI Assistant"])

class AIQueryRequest(BaseModel):
    prompt: str
    session_id: Optional[str] = None

class AIConfirmActionRequest(BaseModel):
    confirmation_token: str

@router.post("/query")
def query_ai_assistant(
    req: AIQueryRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Send natural language query to the CloudVault AI Assistant.
    Provides read-only summaries or prepares controlled action proposals.
    """
    if not req.prompt or not req.prompt.strip():
        raise HTTPException(status_code=400, detail="Query prompt cannot be empty.")

    provider = get_ai_provider()
    result = provider.process_query(current_user.id, req.prompt, db)

    # Record read query in audit log if sensitive
    if result.get("action_card"):
        record_audit_log(
            user_id=current_user.id,
            event_type="AI_ACTION_PROPOSED",
            action=result["action_card"].get("action_type", "UNKNOWN"),
            details={"prompt": req.prompt, "action_type": result["action_card"].get("action_type")},
            db=db
        )

    return result

@router.post("/confirm-action")
def confirm_ai_action(
    req: AIConfirmActionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Execute a previously staged action proposal after explicit user confirmation.
    Re-validates cryptographic token, verifies resource ownership, prevents replay,
    and executes the approved operation.
    """
    is_valid, err, action_type, payload, resource_id = validate_and_consume_token(
        req.confirmation_token,
        current_user.id,
        db
    )

    if not is_valid:
        raise HTTPException(status_code=400, detail=err)

    storage = get_storage_provider()
    execution_result = {}

    # 1. TRIGGER_BACKUP
    if action_type == "TRIGGER_BACKUP":
        plan_id = payload.get("plan_id")
        plan = db.query(BackupPlan).filter(BackupPlan.id == plan_id, BackupPlan.user_id == current_user.id).first()
        if not plan:
            raise HTTPException(status_code=404, detail="Backup plan not found.")

        snap, job = execute_backup_plan(plan.id, current_user, db, storage, trigger_type="AI_ASSISTANT")
        execution_result = {
            "status": "SUCCESS",
            "message": f"Backup completed successfully for plan '{plan.plan_name}'.",
            "snapshot_id": snap.id,
            "snapshot_number": snap.snapshot_number,
            "files_scanned": job.files_scanned,
            "files_uploaded": job.files_uploaded,
            "files_deduplicated": job.files_deduplicated,
            "bytes_saved": job.bytes_deduplicated
        }

    # 2. LOCK_SNAPSHOT
    elif action_type == "LOCK_SNAPSHOT":
        snap_id = payload.get("snapshot_id")
        snap = db.query(Snapshot).filter(Snapshot.id == snap_id, Snapshot.user_id == current_user.id).first()
        if not snap:
            raise HTTPException(status_code=404, detail="Snapshot not found.")

        from datetime import datetime
        snap.is_locked = True
        snap.is_immutable = True
        if payload.get("lock_until"):
            snap.lock_until = datetime.fromisoformat(payload["lock_until"])
        db.commit()

        execution_result = {
            "status": "SUCCESS",
            "message": f"WORM immutable retention locked on Snapshot #{snap.snapshot_number} until {snap.lock_until}.",
            "snapshot_id": snap.id,
            "is_immutable": True,
            "lock_until": snap.lock_until.isoformat() if snap.lock_until else None
        }

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported action type: {action_type}")

    # Record action in audit log
    record_audit_log(
        user_id=current_user.id,
        event_type="AI_ACTION_EXECUTED",
        action=action_type,
        details={"action_type": action_type, "payload": payload, "result": execution_result},
        db=db,
        severity="WARNING"
    )

    return execution_result

@router.get("/capabilities")
def get_ai_capabilities():
    """Return catalog of read-only queries and controlled actions supported by CloudVault AI."""
    return {
        "provider": "RuleBasedLocalLLMProvider (CloudVault Core Native)",
        "read_only_queries": [
            "Protected files count & plan distribution",
            "Recent snapshots list & metadata",
            "Failed or interrupted backup job diagnosis",
            "Storage savings & deduplication efficiency",
            "Unprotected / recently modified local files",
            "Active security & ransomware alert explanations",
            "Overall system backup health assessment",
            "Intelligent backup schedule recommendations"
        ],
        "controlled_actions": [
            "TRIGGER_BACKUP (Requires user authorization)",
            "LOCK_SNAPSHOT (Enforces WORM retention lock)",
            "RESTORE_FILE (Point-in-time recovery proposal)"
        ],
        "safety_controls": [
            "Cryptographically signed single-use HMAC tokens",
            "5-minute token expiration",
            "Anti-replay nonce tracking",
            "Zero prompt-injection data mutation",
            "Immutable audit trail logging"
        ]
    }

