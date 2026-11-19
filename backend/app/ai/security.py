import hmac
import hashlib
import json
import base64
import secrets
from datetime import datetime, timedelta
from typing import Tuple, Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models import AIActionRequest, AuditLog

TOKEN_EXPIRATION_MINUTES = 5

def create_confirmation_token(
    user_id: str,
    action_type: str,
    resource_id: Optional[str],
    proposed_payload: Dict[str, Any],
    db: Session
) -> Tuple[str, Dict[str, Any]]:
    """
    Generate a tamper-evident, cryptographically signed, single-use confirmation token
    bound to the authenticated user, action type, resource, expiry, and a unique nonce.
    """
    nonce = secrets.token_hex(16)
    expires_at = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    exp_timestamp = int(expires_at.timestamp())

    # Payload to sign
    token_data = {
        "uid": user_id,
        "act": action_type,
        "rid": resource_id or "",
        "nce": nonce,
        "exp": exp_timestamp
    }
    payload_bytes = json.dumps(token_data, sort_keys=True).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")

    # HMAC-SHA256 signature
    signature = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    token_str = f"{payload_b64}.{signature}"

    # Persist request in DB to enforce single-use and replay prevention
    action_req = AIActionRequest(
        user_id=user_id,
        action_type=action_type,
        resource_id=resource_id,
        proposed_payload=json.dumps(proposed_payload),
        nonce=nonce,
        is_consumed=False,
        status="PENDING",
        expires_at=expires_at
    )
    db.add(action_req)
    db.commit()

    return token_str, token_data

def validate_and_consume_token(
    token_str: str,
    user_id: str,
    db: Session
) -> Tuple[bool, str, Dict[str, Any], str, str]:
    """
    Validate confirmation token signature, expiration, user ownership, and single-use status.
    If valid, atomically marks the token as consumed.
    Returns: (is_valid, error_msg, action_type, payload_dict, resource_id)
    """
    try:
        parts = token_str.strip().split(".")
        if len(parts) != 2:
            return False, "Malformed confirmation token", "", {}, ""

        payload_b64, signature = parts
        
        # Verify HMAC signature
        expected_sig = hmac.new(
            settings.SECRET_KEY.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            return False, "Invalid cryptographic token signature", "", {}, ""

        # Decode payload
        padding = "=" * (-len(payload_b64) % 4)
        token_data = json.loads(base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8"))

        # Verify user ownership
        if token_data.get("uid") != user_id:
            return False, "Token was not issued to this authenticated user", "", {}, ""

        # Verify expiration
        if datetime.utcnow().timestamp() > token_data.get("exp", 0):
            return False, "Confirmation token has expired. Please initiate request again.", "", {}, ""

        nonce = token_data.get("nce")
        if not nonce:
            return False, "Missing token nonce", "", {}, ""

        # Query database record for replay verification
        action_req = db.query(AIActionRequest).filter(
            AIActionRequest.nonce == nonce,
            AIActionRequest.user_id == user_id
        ).first()

        if not action_req:
            return False, "Action request record not found", "", {}, ""

        if action_req.is_consumed:
            return False, "Replay attack detected: token has already been consumed", "", {}, ""

        # Consume token
        action_req.is_consumed = True
        action_req.status = "EXECUTED"
        action_req.executed_at = datetime.utcnow()
        db.commit()

        payload_dict = json.loads(action_req.proposed_payload)
        return True, "", action_req.action_type, payload_dict, action_req.resource_id or ""

    except Exception as e:
        return False, f"Token validation error: {str(e)}", "", {}, ""

def record_audit_log(
    user_id: str,
    event_type: str,
    action: str,
    details: Dict[str, Any],
    db: Session,
    severity: str = "INFO",
    ip_address: str = "127.0.0.1"
) -> AuditLog:
    """
    Record an immutable, hash-chained audit log entry.
    """
    last_log = db.query(AuditLog).order_by(AuditLog.created_at.desc()).first()
    prev_hash = last_log.current_hash if (last_log and last_log.current_hash) else "GENESIS_BLOCK_00000000000000000000000000000000"

    now = datetime.utcnow()
    details_str = json.dumps(details, sort_keys=True)
    hash_payload = f"{prev_hash}:{user_id}:{event_type}:{action}:{details_str}:{now.isoformat()}"
    current_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

    log_entry = AuditLog(
        user_id=user_id,
        event_type=event_type,
        action=action,
        status="SUCCESS",
        severity=severity,
        ip_address=ip_address,
        details=details_str,
        prev_hash=prev_hash,
        current_hash=current_hash,
        created_at=now
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry

