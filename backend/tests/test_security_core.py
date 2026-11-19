import os
import pytest
from datetime import datetime, timedelta
from fastapi import HTTPException

from backend.app.models import User, BackupPlan, Snapshot
from backend.app.services.crypto_service import (
    derive_user_kek, derive_object_dek, encrypt_payload_aes_gcm, decrypt_payload_aes_gcm,
    generate_totp_secret, compute_totp_code, verify_totp_code,
    generate_recovery_codes, hash_recovery_code
)
from backend.app.routers.auth import (
    setup_mfa, enable_mfa, disable_mfa, login,
    MFAEnableRequest, MFADisableRequest, UserLogin
)
from backend.app.routers.recovery import (
    lock_snapshot_worm, delete_snapshot, LockSnapshotRequest
)

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

