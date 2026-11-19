import os
import pytest
from datetime import datetime, timedelta
from fastapi import HTTPException

from backend.app.models import User, BackupPlan, Snapshot, SnapshotFile, StorageObject, RansomwareAlert, AuditLog
from backend.app.services.crypto_service import (
    derive_user_kek, derive_object_dek, encrypt_payload_aes_gcm, decrypt_payload_aes_gcm,
    generate_totp_secret, compute_totp_code, verify_totp_code,
    generate_recovery_codes, hash_recovery_code,
    envelope_encrypt_payload, envelope_decrypt_payload, rotate_user_kek
)
from backend.app.routers.auth import (
    setup_mfa, enable_mfa, disable_mfa, login,
    MFAEnableRequest, MFADisableRequest, UserLogin,
    get_mfa_status, regenerate_mfa_recovery_codes
)
from backend.app.routers.recovery import (
    lock_snapshot_worm, delete_snapshot, update_snapshot,
    LockSnapshotRequest, UpdateSnapshotRequest
)
from backend.app.ai.security import record_audit_log, verify_audit_log_chain
from backend.app.services.backup_service import execute_backup_plan
from backend.app.services.restore_service import restore_file_by_id
from backend.app.services.ransomware_service import resolve_security_alert
from backend.app.storage.mock_storage import MockStorageProvider
from backend.app.ai.provider import RuleBasedLocalLLMProvider
import json
from pathlib import Path

def test_aes_gcm_envelope_encryption_roundtrip():
    user_id = "user-12345"
    salt = "random_cryptographic_salt_98765"
    plaintext = b"Sensitive academic research data and source code to protect in cloud."
    content_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    kek = derive_user_kek(user_id, salt)
    dek = derive_object_dek(kek, content_hash)
    assert len(dek) == 32

    ciphertext, nonce = encrypt_payload_aes_gcm(plaintext, dek)
    assert ciphertext != plaintext
    assert len(nonce) == 12

    decrypted = decrypt_payload_aes_gcm(ciphertext, dek, nonce)
    assert decrypted == plaintext

def test_aes_gcm_corrupted_ciphertext_fails_auth():
    key = os.urandom(32)
    plaintext = b"Uncorrupted message"
    ciphertext, nonce = encrypt_payload_aes_gcm(plaintext, key)

    # Corrupt 1 byte in ciphertext
    corrupted = bytearray(ciphertext)
    corrupted[5] ^= 0xFF

    with pytest.raises(ValueError) as exc:
        decrypt_payload_aes_gcm(bytes(corrupted), key, nonce)
    assert "Cryptographic verification failed" in str(exc.value)

def test_totp_rfc6238_generation_and_verification():
    secret = generate_totp_secret()
    assert len(secret) >= 16

    code = compute_totp_code(secret)
    assert len(code) == 6
    assert code.isdigit()

    assert verify_totp_code(secret, code) is True
    assert verify_totp_code(secret, "999999") is False

def test_mfa_enable_and_recovery_codes_flow(db_session):
    user = User(email="mfa_test@university.edu", password_hash="hash", full_name="MFA User")
    from backend.app.auth import get_password_hash
    user.password_hash = get_password_hash("Password123!")
    db_session.add(user)
    db_session.commit()

    # 1. Setup MFA
    setup_res = setup_mfa(current_user=user)
    secret = setup_res["secret"]
    assert "otpauth://" in setup_res["otpauth_url"]

    # 2. Enable MFA with valid code
    valid_code = compute_totp_code(secret)
    enable_res = enable_mfa(MFAEnableRequest(secret=secret, code=valid_code), current_user=user, db=db_session)
    assert enable_res["status"] == "SUCCESS"
    assert len(enable_res["recovery_codes"]) == 8
    recovery_code = enable_res["recovery_codes"][0]

    # Verify user state in DB
    db_session.refresh(user)
    assert user.mfa_enabled is True

    # 3. Login without code -> prompts mfa_required
    login_no_mfa = login(UserLogin(email="mfa_test@university.edu", password="Password123!"), db=db_session)
    assert login_no_mfa["mfa_required"] is True
    assert login_no_mfa["access_token"] is None

    # 4. Login with one-time recovery code
    login_with_rec = login(UserLogin(email="mfa_test@university.edu", password="Password123!", mfa_code=recovery_code), db=db_session)
    assert login_with_rec["mfa_required"] is False
    assert login_with_rec["access_token"] is not None

    # 5. REPLAY TEST: Re-using the exact same recovery code must fail!
    with pytest.raises(HTTPException) as exc:
        login(UserLogin(email="mfa_test@university.edu", password="Password123!", mfa_code=recovery_code), db=db_session)
    assert exc.value.status_code == 401

def test_worm_immutable_snapshot_deletion_prevention(db_session):
    user = User(email="worm_user@university.edu", password_hash="hash", full_name="WORM User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="WORM Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    snap = Snapshot(
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="WORM Snapshot"
    )
    db_session.add(snap)
    db_session.commit()

    # 1. Lock snapshot with WORM retention policy (30 days)
    lock_res = lock_snapshot_worm(snap.id, LockSnapshotRequest(retention_days=30), current_user=user, db=db_session)
    assert lock_res["is_immutable"] is True

    # Verify DB state
    db_session.refresh(snap)
    assert snap.is_immutable is True

    # 2. Attempt to delete locked snapshot -> MUST FAIL with HTTP 403 Forbidden!
    with pytest.raises(HTTPException) as exc:
        delete_snapshot(snap.id, current_user=user, db=db_session)
    assert exc.value.status_code == 403
    assert "WORM Immutable Retention Violation" in exc.value.detail


def test_envelope_encryption_random_dek_and_aad():
    user_id = "user_sec_456"
    salt = "random_salt_abc123"
    plaintext = b"Classified enterprise cybersecurity architecture specification."
    aad_context = f"{user_id}:hash1234:1"

    # 1. Envelope Encrypt with fresh random DEK and nonces
    enc_res = envelope_encrypt_payload(
        plaintext=plaintext,
        user_id=user_id,
        salt=salt,
        key_version=1,
        aad_context=aad_context
    )
    assert enc_res["ciphertext"] != plaintext
    assert len(enc_res["payload_nonce"]) == 12
    assert len(enc_res["dek_nonce"]) == 12
    assert enc_res["key_version"] == 1

    # 2. Envelope Decrypt with matching metadata
    decrypted = envelope_decrypt_payload(
        ciphertext=enc_res["ciphertext"],
        encrypted_dek=enc_res["encrypted_dek"],
        payload_nonce=enc_res["payload_nonce"],
        dek_nonce=enc_res["dek_nonce"],
        user_id=user_id,
        salt=salt,
        key_version=1,
        aad_context=aad_context
    )
    assert decrypted == plaintext

    # 3. Wrong Key / Wrong Salt Rejection
    with pytest.raises(ValueError):
        envelope_decrypt_payload(
            ciphertext=enc_res["ciphertext"],
            encrypted_dek=enc_res["encrypted_dek"],
            payload_nonce=enc_res["payload_nonce"],
            dek_nonce=enc_res["dek_nonce"],
            user_id=user_id,
            salt="wrong_salt_xyz999",
            key_version=1,
            aad_context=aad_context
        )

    # 4. Tampered AAD Rejection
    with pytest.raises(ValueError):
        envelope_decrypt_payload(
            ciphertext=enc_res["ciphertext"],
            encrypted_dek=enc_res["encrypted_dek"],
            payload_nonce=enc_res["payload_nonce"],
            dek_nonce=enc_res["dek_nonce"],
            user_id=user_id,
            salt=salt,
            key_version=1,
            aad_context=f"{user_id}:tampered_hash:1"
        )

    # 5. Nonce Uniqueness across 50 operations (Zero Nonce Reuse Guarantee)
    payload_nonces = set()
    dek_nonces = set()
    for _ in range(50):
        res = envelope_encrypt_payload(plaintext, user_id, salt, key_version=1, aad_context=aad_context)
        payload_nonces.add(res["payload_nonce"])
        dek_nonces.add(res["dek_nonce"])
    assert len(payload_nonces) == 50
    assert len(dek_nonces) == 50


def test_crypto_key_rotation_preserves_older_backups(db_session):
    from backend.app.auth import get_password_hash
    user = User(email="rotation_user@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Rotation User", encryption_salt="salt_rot_001")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    data1 = b"Data encrypted under key version 1"
    enc1 = envelope_encrypt_payload(data1, user.id, user.encryption_salt, key_version=1, aad_context="ctx1")
    assert enc1["key_version"] == 1

    # Rotate KEK
    new_ver = rotate_user_kek(user.id, db_session)
    assert new_ver == 2
    assert user.current_key_version == 2

    # Encrypt second data under version 2
    data2 = b"Data encrypted under rotated key version 2"
    enc2 = envelope_encrypt_payload(data2, user.id, user.encryption_salt, key_version=2, aad_context="ctx2")
    assert enc2["key_version"] == 2

    # Verify BOTH payloads decrypt successfully under their respective versions
    dec1 = envelope_decrypt_payload(enc1["ciphertext"], enc1["encrypted_dek"], enc1["payload_nonce"], enc1["dek_nonce"], user.id, user.encryption_salt, key_version=1, aad_context="ctx1")
    dec2 = envelope_decrypt_payload(enc2["ciphertext"], enc2["encrypted_dek"], enc2["payload_nonce"], enc2["dek_nonce"], user.id, user.encryption_salt, key_version=2, aad_context="ctx2")

    assert dec1 == data1
    assert dec2 == data2


def test_end_to_end_encrypted_backup_and_restore_pipeline(tmp_path, db_session):
    from backend.app.auth import get_password_hash
    user = User(email="pipeline_enc@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Pipeline User", encryption_salt="pipeline_salt_777")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    src_dir = tmp_path / "enc_src"
    src_dir.mkdir()
    doc_file = src_dir / "research_paper.pdf"
    content = b"%PDF-1.4 Zero-Trust Encrypted Cloud Backup Research Payload." * 50
    doc_file.write_bytes(content)

    plan = BackupPlan(
        user_id=user.id,
        plan_name="Encrypted Plan",
        source_directories=json.dumps([str(src_dir)]),
        encryption_enabled=True,
        compression_algo="gzip"
    )
    db_session.add(plan)
    db_session.commit()
    db_session.refresh(plan)

    storage = MockStorageProvider(base_dir=str(tmp_path / "mock_store"))

    # 1. Take Encrypted Backup
    snap, job = execute_backup_plan(plan.id, user, db_session, storage)
    assert snap.total_files == 1
    assert job.status == "SUCCESS"

    # Verify StorageObject is marked as encrypted with envelope metadata
    obj = db_session.query(StorageObject).filter(StorageObject.user_id == user.id).first()
    assert obj is not None
    assert obj.is_encrypted is True
    assert obj.encryption_algo == "AES-256-GCM"
    assert obj.encrypted_dek is not None
    assert obj.dek_nonce is not None
    assert obj.encryption_nonce is not None

    # Verify stored bytes in storage are CIPHERTEXT (cannot be decompressed as raw gzip)
    raw_stored_bytes = storage.download_bytes(obj.storage_path)
    import gzip
    with pytest.raises(Exception):
        gzip.decompress(raw_stored_bytes)

    # 2. Restore and verify bit-for-bit SHA-256 integrity
    snap_file = snap.files[0]
    dest_dir = tmp_path / "restored_enc"
    restore_res = restore_file_by_id(snap_file.id, str(dest_dir), "overwrite", db_session, storage)
    assert restore_res["status"] == "RESTORED"
    assert restore_res["sha256_verified"] is True
    restored_bytes = Path(restore_res["path"]).read_bytes()
    assert restored_bytes == content

    # 3. Deduplication Preservation: backup identical file again under same user
    snap2, job2 = execute_backup_plan(plan.id, user, db_session, storage)
    assert job2.files_uploaded == 0
    assert job2.files_deduplicated == 1
    db_session.refresh(obj)
    assert obj.ref_count == 2


def test_backward_compatibility_unencrypted_restore(tmp_path, db_session):
    from backend.app.auth import get_password_hash
    user = User(email="unenc_user@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Unenc User")
    db_session.add(user)
    db_session.commit()

    src_dir = tmp_path / "unenc_src"
    src_dir.mkdir()
    doc_file = src_dir / "plain.txt"
    content = b"Unencrypted historical backup file that should restore cleanly."
    doc_file.write_bytes(content)

    plan = BackupPlan(
        user_id=user.id,
        plan_name="Unencrypted Plan",
        source_directories=json.dumps([str(src_dir)]),
        encryption_enabled=False
    )
    db_session.add(plan)
    db_session.commit()

    storage = MockStorageProvider(base_dir=str(tmp_path / "mock_store_unenc"))
    snap, _ = execute_backup_plan(plan.id, user, db_session, storage)

    obj = db_session.query(StorageObject).filter(StorageObject.user_id == user.id).first()
    assert obj.is_encrypted is False

    dest = tmp_path / "restored_unenc"
    res = restore_file_by_id(snap.files[0].id, str(dest), "overwrite", db_session, storage)
    assert res["status"] == "RESTORED"
    assert Path(res["path"]).read_bytes() == content


def test_mfa_brute_force_rate_limiting(db_session):
    from backend.app.auth import get_password_hash
    user = User(email="ratelimit_mfa@univ.edu", password_hash=get_password_hash("Password123!"), full_name="Rate Limit User")
    db_session.add(user)
    db_session.commit()

    # Enable MFA
    sec = generate_totp_secret()
    valid_code = compute_totp_code(sec)
    enable_mfa(MFAEnableRequest(secret=sec, code=valid_code), current_user=user, db=db_session)

    # 4 consecutive incorrect attempts
    for attempt in range(1, 5):
        with pytest.raises(HTTPException) as exc:
            login(UserLogin(email="ratelimit_mfa@univ.edu", password="Password123!", mfa_code="000000"), db=db_session)
        assert exc.value.status_code == 401

    # 5th attempt triggers temporary lockout (HTTP 429)
    with pytest.raises(HTTPException) as exc:
        login(UserLogin(email="ratelimit_mfa@univ.edu", password="Password123!", mfa_code="000000"), db=db_session)
    assert exc.value.status_code == 429
    assert "temporarily locked" in exc.value.detail

    # Subsequent attempt within lockout window immediately returns HTTP 429
    with pytest.raises(HTTPException) as exc:
        login(UserLogin(email="ratelimit_mfa@univ.edu", password="Password123!", mfa_code="123456"), db=db_session)
    assert exc.value.status_code == 429


def test_mfa_disable_requires_password_and_totp(db_session):
    from backend.app.auth import get_password_hash
    user = User(email="disable_mfa_test@univ.edu", password_hash=get_password_hash("ValidPass123!"), full_name="Disable MFA User")
    db_session.add(user)
    db_session.commit()

    sec = generate_totp_secret()
    valid_code = compute_totp_code(sec)
    enable_mfa(MFAEnableRequest(secret=sec, code=valid_code), current_user=user, db=db_session)

    # Disable with wrong password -> HTTP 401
    with pytest.raises(HTTPException) as exc:
        disable_mfa(MFADisableRequest(password="WrongPassword!", code=valid_code), current_user=user, db=db_session)
    assert exc.value.status_code == 401

    # Disable with wrong TOTP -> HTTP 400
    with pytest.raises(HTTPException) as exc:
        disable_mfa(MFADisableRequest(password="ValidPass123!", code="999999"), current_user=user, db=db_session)
    assert exc.value.status_code == 400

    # Disable with valid credentials -> Success
    res = disable_mfa(MFADisableRequest(password="ValidPass123!", code=valid_code), current_user=user, db=db_session)
    assert res["status"] == "SUCCESS"
    db_session.refresh(user)
    assert user.mfa_enabled is False
    assert user.mfa_secret is None


def test_worm_modification_prevention_and_provider_labeling(db_session):
    from backend.app.auth import get_password_hash
    user = User(email="worm_mod@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="WORM Mod User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Plan WORM", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    snap = Snapshot(plan_id=plan.id, user_id=user.id, snapshot_number=1, name="Snapshot Alpha")
    db_session.add(snap)
    db_session.commit()

    # Lock with WORM retention
    lock_res = lock_snapshot_worm(snap.id, LockSnapshotRequest(retention_days=45), current_user=user, db=db_session)
    assert lock_res["is_immutable"] is True
    assert lock_res["retention_mode"] == "SIMULATED"
    assert lock_res["provider_lock_type"] == "MOCK_SIMULATED"

    # Attempt to modify snapshot name -> MUST FAIL with HTTP 403 Forbidden!
    with pytest.raises(HTTPException) as exc:
        update_snapshot(snap.id, UpdateSnapshotRequest(name="Tampered Name"), current_user=user, db=db_session)
    assert exc.value.status_code == 403
    assert "WORM Immutable Retention Violation" in exc.value.detail


def test_alert_resolution_does_not_remove_active_worm_lock(db_session):
    from backend.app.auth import get_password_hash
    user = User(email="worm_persist@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="WORM Persist User")
    db_session.add(user)
    db_session.commit()

    plan = BackupPlan(user_id=user.id, plan_name="Persist Plan", source_directories="[]")
    db_session.add(plan)
    db_session.commit()

    snap = Snapshot(plan_id=plan.id, user_id=user.id, snapshot_number=1, name="Baseline Snapshot")
    db_session.add(snap)
    db_session.commit()

    # Lock with 30-day WORM retention
    lock_snapshot_worm(snap.id, LockSnapshotRequest(retention_days=30), current_user=user, db=db_session)
    db_session.refresh(snap)
    assert snap.is_immutable is True

    # Simulate ransomware alert for this plan
    alert = RansomwareAlert(
        user_id=user.id,
        plan_id=plan.id,
        risk_score=85,
        alert_level="QUARANTINED",
        status="ACTIVE"
    )
    db_session.add(alert)
    db_session.commit()

    # Resolve alert with unquarantine_snapshots=True
    resolve_security_alert(alert.id, user.id, "Threat resolved and safe", unquarantine_snapshots=True, db=db_session)

    # Active WORM retention lock MUST STILL BE LOCKED!
    db_session.refresh(snap)
    assert snap.is_immutable is True
    assert snap.is_locked is True


def test_audit_hash_chain_verification_and_tampering_detection(db_session):
    from backend.app.auth import get_password_hash
    user = User(email="audit_chain@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="Audit User")
    db_session.add(user)
    db_session.commit()

    # Record 3 sequential audit logs
    log1 = record_audit_log(user.id, "AUTH_LOGIN", "Login success", {"ip": "10.0.0.1"}, db=db_session)
    log2 = record_audit_log(user.id, "BACKUP_COMPLETED", "Backup Snapshot #1 created", {"files": 12}, db=db_session)
    log3 = record_audit_log(user.id, "SNAPSHOT_LOCKED", "Locked snapshot #1 with WORM", {"days": 30}, db=db_session)

    # Verify unbroken chain
    res = verify_audit_log_chain(user.id, db_session)
    assert res["is_valid"] is True
    assert res["verified_entries"] >= 3
    assert res["broken_entry_id"] is None

    # TAMPERING INJECTION: Alter action text of log2 directly in database
    log2.action = "TAMPERED: Attacker modified action text"
    db_session.commit()

    # Re-run verification -> MUST DETECT TAMPERING!
    tamper_res = verify_audit_log_chain(user.id, db_session)
    assert tamper_res["is_valid"] is False
    assert tamper_res["broken_entry_id"] == log2.id
    assert "tampered" in tamper_res["error_message"].lower() or "broken" in tamper_res["error_message"].lower()


def test_ai_assistant_phase4_security_queries(db_session):
    from backend.app.auth import get_password_hash
    user = User(email="ai_sec_eval@univ.edu", password_hash=get_password_hash("Pass123!"), full_name="AI Sec User", encryption_salt="ai_sec_salt_999")
    db_session.add(user)
    db_session.commit()

    ai_provider = RuleBasedLocalLLMProvider()

    # 1. "Are my backups encrypted?"
    q1 = ai_provider.process_query(user.id, "Are my backups encrypted?", db_session)
    assert "Zero-Trust Encryption Status" in q1["response"]
    assert "AES-256-GCM" in q1["response"]

    # 2. "Is MFA enabled?"
    q2 = ai_provider.process_query(user.id, "Is MFA enabled?", db_session)
    assert "Multi-Factor Authentication" in q2["response"]

    # 3. "Which snapshots are protected?"
    q3 = ai_provider.process_query(user.id, "Which snapshots are protected?", db_session)
    assert "WORM Protected Snapshots" in q3["response"]

    # 4. "When does a retention lock expire?"
    q4 = ai_provider.process_query(user.id, "When does a retention lock expire?", db_session)
    assert "WORM Retention Expiry Schedule" in q4["response"]

    # 5. "Has my audit trail been tampered with?"
    q5 = ai_provider.process_query(user.id, "Has my audit trail been tampered with?", db_session)
    assert "Audit Trail Tamper-Evidence Verification" in q5["response"]

    # 6. "Are my files safe to restore?"
    q6 = ai_provider.process_query(user.id, "Are my files safe to restore?", db_session)
    assert "File Restoration Safety Assessment" in q6["response"]

    # 7. "What security improvements do I need?"
    q7 = ai_provider.process_query(user.id, "What security improvements do I need?", db_session)
    assert "Comprehensive Cyber Resilience Checklist" in q7["response"]


