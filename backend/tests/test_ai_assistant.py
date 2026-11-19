import pytest
import json
import gzip
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from backend.app.models import User, BackupPlan, Snapshot, SnapshotFile, StorageObject, BackupJob, AuditLog
from backend.app.routers.ai import query_ai_assistant, confirm_ai_action, get_ai_capabilities, AIQueryRequest, AIConfirmActionRequest
from backend.app.ai.security import create_confirmation_token, validate_and_consume_token, record_audit_log
from backend.app.ai.provider import get_ai_provider, ExternalLLMProvider, RuleBasedLocalLLMProvider
from backend.app.storage import get_storage_provider
from fastapi import HTTPException

def test_ai_capabilities():
    caps = get_ai_capabilities()
    assert "read_only_queries" in caps
    assert "controlled_actions" in caps
    assert "safety_controls" in caps
    assert len(caps["read_only_queries"]) >= 5

def test_ai_read_only_queries(db_session):
    # 1. Create User A and User B
    user_a = User(email="ai_user_a@university.edu", password_hash="hash", full_name="User A")
    user_b = User(email="ai_user_b@university.edu", password_hash="hash", full_name="User B")
    db_session.add_all([user_a, user_b])
    db_session.commit()

    # Create plan and snapshot for User A only
    plan_a = BackupPlan(
        user_id=user_a.id,
        plan_name="Research Data Plan",
        source_directories=json.dumps(["C:/Data"]),
        schedule_type="interval"
    )
    db_session.add(plan_a)
    db_session.commit()

    snap_a = Snapshot(
        plan_id=plan_a.id,
        user_id=user_a.id,
        snapshot_number=1,
        name="Snapshot #1",
        total_files=42,
        total_uncompressed_bytes=1048576,
        total_stored_bytes=524288
    )
    db_session.add(snap_a)
    db_session.commit()

    # User A query: "How many files are currently protected?"
    req_a = AIQueryRequest(prompt="How many files are currently protected?")
    res_a = query_ai_assistant(req_a, current_user=user_a, db=db_session)
    assert res_a["action_card"] is None
    assert "42" in res_a["response"] or "Protected" in res_a["response"]

    # User B query: Must be isolated (User B has 0 files)
    req_b = AIQueryRequest(prompt="How many files are currently protected?")
    res_b = query_ai_assistant(req_b, current_user=user_b, db=db_session)
    assert "0 files" in res_b["response"] or res_b["data"]["protected_files_count"] == 0

    # User A query: "Show my last five backups."
    req_snaps = AIQueryRequest(prompt="Show my last five backups")
    res_snaps = query_ai_assistant(req_snaps, current_user=user_a, db=db_session)
    assert len(res_snaps["data"]["snapshots"]) == 1
    assert "Snapshot #1" in res_snaps["response"]

    # User A query: "Is my backup system healthy?"
    req_health = AIQueryRequest(prompt="Is my backup system healthy?")
    res_health = query_ai_assistant(req_health, current_user=user_a, db=db_session)
    assert "health_score" in res_health["data"]
    assert "Health Assessment" in res_health["response"]

def test_ai_controlled_action_and_replay_protection(db_session, monkeypatch):
    user = User(email="action_user@university.edu", password_hash="hash", full_name="Action User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(
        user_id=user.id,
        plan_name="Project Alpha",
        source_directories=json.dumps(["."]),
        schedule_type="interval"
    )
    db_session.add(plan)
    db_session.commit()

    snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Initial Snap"
    )
    db_session.add(snap)
    db_session.commit()

    # 1. Ask AI to lock snapshot
    req_lock = AIQueryRequest(prompt="Lock snapshot with WORM immutable retention")
    res_lock = query_ai_assistant(req_lock, current_user=user, db=db_session)
    assert res_lock["action_card"] is not None
    token = res_lock["action_card"]["confirmation_token"]
    assert token is not None

    # 2. Confirm execution of the action
    req_confirm = AIConfirmActionRequest(confirmation_token=token)
    confirm_res = confirm_ai_action(req_confirm, current_user=user, db=db_session)
    assert confirm_res["status"] == "SUCCESS"
    assert confirm_res["is_immutable"] is True

    # Check snapshot in DB is now locked
    db_session.refresh(snap)
    assert snap.is_immutable is True
    assert snap.is_locked is True

    # 3. REPLAY ATTACK TEST: Confirming the exact same token a second time must FAIL
    with pytest.raises(HTTPException) as exc:
        confirm_ai_action(req_confirm, current_user=user, db=db_session)
    assert exc.value.status_code == 400
    assert "replay" in exc.value.detail.lower()

def test_ai_cross_user_token_protection(db_session):
    user_alice = User(email="alice@university.edu", password_hash="hash", full_name="Alice")
    user_eve = User(email="eve@university.edu", password_hash="hash", full_name="Eve")
    db_session.add_all([user_alice, user_eve])
    db_session.commit()

    plan_alice = BackupPlan(user_id=user_alice.id, plan_name="Alice Work", source_directories="[]")
    db_session.add(plan_alice)
    db_session.commit()

    # Create token for Alice
    token_alice, _ = create_confirmation_token(user_alice.id, "TRIGGER_BACKUP", plan_alice.id, {"plan_id": plan_alice.id}, db_session)

    # Eve tries to consume Alice's confirmation token -> MUST BE BLOCKED
    req_eve = AIConfirmActionRequest(confirmation_token=token_alice)
    with pytest.raises(HTTPException) as exc:
        confirm_ai_action(req_eve, current_user=user_eve, db=db_session)
    assert exc.value.status_code == 400
    assert "not issued to this authenticated user" in exc.value.detail

def test_ai_audit_log_hash_chaining(db_session):
    user = User(email="audit_user@university.edu", password_hash="hash", full_name="Audited User")
    db_session.add(user)
    db_session.commit()

    log1 = record_audit_log(user.id, "TEST_EVENT_1", "ACTION_1", {"key": "val1"}, db_session)
    assert log1.current_hash != ""
    assert log1.prev_hash != ""

    log2 = record_audit_log(user.id, "TEST_EVENT_2", "ACTION_2", {"key": "val2"}, db_session)
    assert log2.prev_hash == log1.current_hash

def test_ai_milestone_restore_file_flow(db_session, tmp_path):
    """
    Demonstrate Milestone 1:
    1. Authenticated user asks 'How many files are currently protected?'
    2. User asks to restore a file.
    3. Assistant displays exact proposed restoration with short-lived HMAC token.
    4. User explicitly confirms execution.
    5. Backend validates authorization, checks single-use nonce, extracts & verifies SHA-256, writes file.
    6. Operation appears in audit log with hash-chaining.
    7. Replay attack attempt on confirmation token fails.
    """
    storage = get_storage_provider()
    user = User(email="milestone_user@university.edu", password_hash="hash", full_name="Milestone User")
    db_session.add(user)
    db_session.commit()

    # Create plan and snapshot
    plan = BackupPlan(user_id=user.id, plan_name="Thesis Defense", source_directories=json.dumps(["."]))
    db_session.add(plan)
    db_session.commit()

    snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Final Thesis Submission",
        total_files=1,
        total_uncompressed_bytes=100,
        total_stored_bytes=80
    )
    db_session.add(snap)
    db_session.commit()

    # Put a real compressed file into storage
    content = b"CloudVault 2.0 AI Milestone Verified Data Payload"
    sha = hashlib.sha256(content).hexdigest()
    compressed = gzip.compress(content)
    storage_path = f"objects/{sha}"
    storage.upload_bytes(compressed, storage_path)

    so = StorageObject(
        user_id=user.id,
        sha256_hash=sha,
        original_size=len(content),
        compressed_size=len(compressed),
        compression_algo="gzip",
        storage_provider="mock",
        storage_path=storage_path,
        ref_count=1
    )
    db_session.add(so)
    db_session.commit()

    sf = SnapshotFile(
        snapshot_id=snap.id,
        storage_object_id=so.id,
        relative_path="documents/thesis.pdf",
        file_name="thesis.pdf",
        file_size=len(content),
        modified_at=datetime.utcnow()
    )
    db_session.add(sf)
    db_session.commit()

    # Step 1: User asks: "How many files are currently protected?"
    req1 = AIQueryRequest(prompt="How many files are currently protected?")
    res1 = query_ai_assistant(req1, current_user=user, db=db_session)
    assert res1["action_card"] is None
    assert "1 files" in res1["response"] or res1["data"]["protected_files_count"] == 1

    # Step 2: User asks to restore a file
    req2 = AIQueryRequest(prompt="Please restore a file for me.")
    res2 = query_ai_assistant(req2, current_user=user, db=db_session)
    assert res2["action_card"] is not None
    action_card = res2["action_card"]
    assert action_card["action_type"] == "RESTORE_FILE"
    assert "thesis.pdf" in res2["response"]
    assert action_card["proposed_action"]["file_name"] == "thesis.pdf"
    token = action_card["confirmation_token"]
    assert token is not None

    # Step 3: User explicitly confirms execution
    confirm_req = AIConfirmActionRequest(confirmation_token=token)
    confirm_res = confirm_ai_action(confirm_req, current_user=user, db=db_session)

    assert confirm_res["status"] == "SUCCESS"
    assert confirm_res["file_name"] == "thesis.pdf"
    assert confirm_res["sha256_verified"] is True
    restored_file = Path(confirm_res["restored_path"])
    assert restored_file.exists()
    assert restored_file.read_bytes() == content

    # Step 4: Verify operation appears in the audit log
    audit_entry = db_session.query(AuditLog).filter(
        AuditLog.user_id == user.id,
        AuditLog.event_type == "AI_ACTION_EXECUTED"
    ).order_by(AuditLog.created_at.desc()).first()

    assert audit_entry is not None
    assert audit_entry.current_hash != ""
    details = json.loads(audit_entry.details)
    assert details["action_type"] == "RESTORE_FILE"
    assert details["result"]["file_name"] == "thesis.pdf"

    # Step 5: Verify anti-replay protection (cannot confirm the same token again)
    with pytest.raises(HTTPException) as exc:
        confirm_ai_action(confirm_req, current_user=user, db=db_session)
    assert exc.value.status_code == 400
    assert "replay" in exc.value.detail.lower()

def test_ai_all_ten_example_queries(db_session):
    """Verify all 10 user example queries from prompt are processed cleanly."""
    user = User(email="all_queries_user@university.edu", password_hash="hash", full_name="Query User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Work", source_directories=json.dumps(["."]))
    db_session.add(plan)
    db_session.commit()

    snap = Snapshot(plan_id=plan.id, user_id=user.id, snapshot_number=1, name="Snap 1", total_files=5, total_uncompressed_bytes=1000, total_stored_bytes=500)
    db_session.add(snap)
    db_session.commit()

    queries = [
        "How many files are currently protected?",
        "Show my latest five backups.",
        "Which backups failed?",
        "How much storage have I saved through deduplication?",
        "Which files have not been backed up recently?",
        "Explain my latest backup failure.",
        "Is my backup system healthy?",
        "How can I improve my backup protection?",
        "Show my recent snapshots.",
        "Explain my storage usage."
    ]

    for q in queries:
        req = AIQueryRequest(prompt=q)
        res = query_ai_assistant(req, current_user=user, db=db_session)
        assert res is not None
        assert "response" in res
        assert len(res["response"]) > 10

def test_ai_external_llm_fallback_resilience(db_session, monkeypatch):
    """Verify ExternalLLMProvider falls back gracefully to Local Rules when external LLM fails."""
    user = User(email="llm_user@university.edu", password_hash="hash", full_name="LLM User")
    db_session.add(user)
    db_session.commit()

    # Simulate configured LLM provider with invalid URL to test network failure resilience
    provider = ExternalLLMProvider(api_key="sk-dummy-test-key", base_url="http://127.0.0.1:54321/nonexistent")
    res = provider.process_query(user.id, "How many files are currently protected?", db_session)
    assert res is not None
    assert "Protected Files Summary" in res["response"]
    assert "Notice: External LLM was unavailable" in res["response"]
