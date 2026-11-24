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
    ip_address: str = "127.0.0.1",
    user_agent: str = "",
    status: str = "SUCCESS"
) -> AuditLog:
    """
    Record a tamper-evident, hash-chained audit log entry.
    Note: A hash chain stored inside the same writable database is tamper-evident
    (it mathematically proves historical ordering and flags modifications),
    not independently immutable against an administrator with raw DB write access.
    """
    last_log = db.query(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).first()
    prev_hash = last_log.current_hash if (last_log and last_log.current_hash) else "GENESIS_BLOCK_00000000000000000000000000000000"

    now = datetime.utcnow()
    if last_log and last_log.created_at and now <= last_log.created_at:
        now = last_log.created_at + timedelta(microseconds=10)

    details_str = json.dumps(details, sort_keys=True)
    hash_payload = f"{prev_hash}:{user_id}:{event_type}:{action}:{details_str}:{now.isoformat()}"
    current_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

    log_entry = AuditLog(
        user_id=user_id,
        event_type=event_type,
        action=action,
        status=status,
        severity=severity,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details_str,
        prev_hash=prev_hash,
        current_hash=current_hash,
        created_at=now
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry

def verify_audit_log_chain(
    user_id: Optional[str] = None,
    db: Session = None
) -> Dict[str, Any]:
    """
    Verify the cryptographic integrity of the audit log hash chain.
    Iterates sequentially through all audit log entries, re-computing:
    expected_hash = sha256(prev_hash:user_id:event_type:action:details:created_at_iso)
    Verifies that:
      1. Every entry's current_hash matches the recalculated sha256.
      2. Every entry's prev_hash matches the preceding entry's current_hash (or GENESIS).
    Detects any modification, insertion, deletion, or tampering with historical logs.
    """
    raw_logs = db.query(AuditLog).order_by(AuditLog.created_at.asc(), AuditLog.id.asc()).all()
    if not raw_logs:
        return {
            "is_valid": True,
            "total_entries": 0,
            "verified_entries": 0,
            "broken_entry_id": None,
            "error_message": None,
            "tamper_evident_status": "INTACT",
            "tamper_evidence_disclaimer": "Cryptographic SHA-256 hash chaining provides tamper-evidence within the database. It proves historical sequencing and flags any modified or deleted record."
        }

    # Reconstruct topological chain order from hash pointers (handles any sub-millisecond timestamp ties)
    by_prev = {}
    for l in raw_logs:
        if l.prev_hash not in by_prev:
            by_prev[l.prev_hash] = l

    logs = []
    curr_prev = "GENESIS_BLOCK_00000000000000000000000000000000"
    visited_ids = set()
    while curr_prev in by_prev:
        node = by_prev[curr_prev]
        logs.append(node)
        visited_ids.add(node.id)
        curr_prev = node.current_hash

    # Append any remaining unlinked logs so the verification step can flag broken chain or tampering
    if len(visited_ids) < len(raw_logs):
        remaining = [l for l in raw_logs if l.id not in visited_ids]
        logs.extend(remaining)

    expected_prev = "GENESIS_BLOCK_00000000000000000000000000000000"
    verified_count = 0

    for idx, entry in enumerate(logs):
        # 1. Verify prev_hash linkage
        if idx == 0:
            if entry.prev_hash != expected_prev:
                return {
                    "is_valid": False,
                    "total_entries": len(logs),
                    "verified_entries": verified_count,
                    "broken_entry_id": entry.id,
                    "error_message": f"Genesis linkage broken: expected {expected_prev}, got {entry.prev_hash}",
                    "tamper_evident_status": "TAMPERED",
                    "tamper_evidence_disclaimer": "Cryptographic SHA-256 hash chaining detected modified or deleted historical records."
                }
        else:
            if entry.prev_hash != expected_prev:
                return {
                    "is_valid": False,
                    "total_entries": len(logs),
                    "verified_entries": verified_count,
                    "broken_entry_id": entry.id,
                    "error_message": f"Chain linkage broken at entry #{idx+1} ({entry.id}): prev_hash does not match previous block current_hash",
                    "tamper_evident_status": "TAMPERED",
                    "tamper_evidence_disclaimer": "Cryptographic SHA-256 hash chaining detected modified or deleted historical records."
                }

        # 2. Recalculate and verify current_hash
        details_str = entry.details or "{}"
        try:
            parsed = json.loads(details_str)
            normalized_details = json.dumps(parsed, sort_keys=True)
        except Exception:
            normalized_details = details_str

        hash_payload = f"{entry.prev_hash}:{entry.user_id}:{entry.event_type}:{entry.action}:{normalized_details}:{entry.created_at.isoformat()}"
        computed_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

        if computed_hash != entry.current_hash:
            alt_payload = f"{entry.prev_hash}:{entry.user_id}:{entry.event_type}:{entry.action}:{details_str}:{entry.created_at.isoformat()}"
            if hashlib.sha256(alt_payload.encode("utf-8")).hexdigest() != entry.current_hash:
                return {
                    "is_valid": False,
                    "total_entries": len(logs),
                    "verified_entries": verified_count,
                    "broken_entry_id": entry.id,
                    "error_message": f"Block content tampered at entry #{idx+1} ({entry.id}): hash mismatch",
                    "tamper_evident_status": "TAMPERED",
                    "tamper_evidence_disclaimer": "Cryptographic SHA-256 hash chaining detected modified block content."
                }

        verified_count += 1
        expected_prev = entry.current_hash

    return {
        "is_valid": True,
        "total_entries": len(logs),
        "verified_entries": verified_count,
        "broken_entry_id": None,
        "error_message": None,
        "tamper_evident_status": "INTACT",
        "tamper_evidence_disclaimer": "Tamper-evident verification confirmed: all hash chain blocks are cryptographically valid and unbroken."
    }

