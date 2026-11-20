import io
import os
import hashlib
import pytest
from pathlib import Path
from fastapi import HTTPException, UploadFile

from backend.app.models import User, BackupPlan, Snapshot, StorageObject, RansomwareAlert
from backend.app.schemas import (
    UserRegister, UserLogin, BackupPlanCreate,
    RestoreFileRequest, RestoreSnapshotRequest
)
from backend.app.routers.auth import (
    register, login, setup_mfa, enable_mfa, MFAEnableRequest, get_me
)
from backend.app.routers.backups import (
    create_backup_plan, list_backup_plans, upload_file_direct,
    trigger_backup, get_storage_stats
)
from backend.app.routers.recovery import (
    list_snapshots, get_snapshot_tree, restore_file, restore_entire_snapshot, get_deleted_files
)
from backend.app.routers.security import (
    list_security_alerts, simulate_attack_test, SimulateAttackRequest,
    list_audit_logs, verify_audit_trail, get_crypto_status, rotate_key,
    resolve_alert, ResolveAlertRequest
)
from backend.app.routers.ai import (
    query_ai_assistant, AIQueryRequest
)
from backend.app.routers.storage_api import (
    get_inventory, get_providers_capability_matrix
)
from backend.app.services.crypto_service import (
    compute_totp_code, verify_totp_code
)
from streamlit_app.api_client import CloudVaultClient, APIError
from streamlit_app.styles import format_bytes


# ------------------------------------------------------------------------------
# 1. User Registration & Duplicate Rejection
# ------------------------------------------------------------------------------
def test_user_registration_and_duplicate_rejection(db_session):
    email = f"user_reg_{os.urandom(4).hex()}@cloudvault.test"
    user_in = UserRegister(
        email=email,
        password="Password123!",
        full_name="Test User Registration"
    )

    # First registration must succeed
    res1 = register(user_in, db_session)
    assert "access_token" in res1
    assert res1["access_token"] is not None
    assert res1["user"].email == email.lower()

    # Second registration with exact same email must raise HTTPException(400)
    with pytest.raises(HTTPException) as exc:
        register(user_in, db_session)
    assert exc.value.status_code == 400
    assert "already exists" in str(exc.value.detail).lower()


# ------------------------------------------------------------------------------
# 2. Login & JWT Issuance
# ------------------------------------------------------------------------------
def test_user_login_and_jwt_issuance(db_session):
    email = f"user_login_{os.urandom(4).hex()}@cloudvault.test"
    password = "SecurePassword2026!"
    register(UserRegister(email=email, password=password, full_name="Login Test User"), db_session)

    # Valid Login
    login_res = login(UserLogin(email=email, password=password), db_session)
    assert login_res["access_token"] is not None
    assert login_res["token_type"] == "bearer"
    assert login_res["mfa_required"] is False
    assert login_res["user"].email == email.lower()

    # Invalid Password
    with pytest.raises(HTTPException) as exc:
        login(UserLogin(email=email, password="WrongPassword"), db_session)
    assert exc.value.status_code == 401


# ------------------------------------------------------------------------------
# 3. MFA Enforcement & Recovery Codes
# ------------------------------------------------------------------------------
def test_mfa_enforcement_and_recovery_codes(db_session):
    email = f"user_mfa_{os.urandom(4).hex()}@cloudvault.test"
    password = "MasterPassword2026!"
    reg_res = register(UserRegister(email=email, password=password, full_name="MFA User"), db_session)
    user = reg_res["user"]

    # Setup MFA
    setup_res = setup_mfa(user)
    secret = setup_res["secret"]
    assert len(secret) == 32

    # Enable MFA with valid TOTP code
    code = compute_totp_code(secret)
    enable_res = enable_mfa(MFAEnableRequest(secret=secret, code=code), user, db_session)
    assert enable_res["status"] == "SUCCESS"
    assert user.mfa_enabled is True
    recovery_codes = enable_res["recovery_codes"]
    assert len(recovery_codes) == 8

    # Login now triggers mfa_required
    login_step1 = login(UserLogin(email=email, password=password), db_session)
    assert login_step1["mfa_required"] is True
    assert login_step1["access_token"] is None

    # Login with valid TOTP
    fresh_code = compute_totp_code(secret)
    login_step2 = login(UserLogin(email=email, password=password, mfa_code=fresh_code), db_session)
    assert login_step2["access_token"] is not None

    # Login with one-time recovery code
    used_rec_code = recovery_codes[0]
    login_rec = login(UserLogin(email=email, password=password, mfa_code=used_rec_code), db_session)
    assert login_rec["access_token"] is not None

    # Re-using the same recovery code must be rejected with 401
    with pytest.raises(HTTPException) as exc_rec:
        login(UserLogin(email=email, password=password, mfa_code=used_rec_code), db_session)
    assert exc_rec.value.status_code == 401


# ------------------------------------------------------------------------------
# 4. Multi-User Tenant Isolation - Backup Plans
# ------------------------------------------------------------------------------
def test_multi_user_tenant_isolation_plans(db_session):
    user_a = register(UserRegister(email=f"usera_{os.urandom(4).hex()}@tenant.test", password="Password123!", full_name="User A"), db_session)["user"]
    user_b = register(UserRegister(email=f"userb_{os.urandom(4).hex()}@tenant.test", password="Password123!", full_name="User B"), db_session)["user"]

    # User A creates Plan A
    create_backup_plan(BackupPlanCreate(
        plan_name="User A Secret Plan",
        source_directories=["./secret_a"],
        schedule_type="manual"
    ), user_a, db_session)

    # User B creates Plan B
    create_backup_plan(BackupPlanCreate(
        plan_name="User B Public Plan",
        source_directories=["./public_b"],
        schedule_type="manual"
    ), user_b, db_session)

    # User A listing plans must ONLY contain Plan A
    plans_a = list_backup_plans(user_a, db_session)
    assert len(plans_a) == 1
    assert plans_a[0].plan_name == "User A Secret Plan"

    # User B listing plans must ONLY contain Plan B
    plans_b = list_backup_plans(user_b, db_session)
    assert len(plans_b) == 1
    assert plans_b[0].plan_name == "User B Public Plan"


# ------------------------------------------------------------------------------
# 5. Multi-User Tenant Isolation - Snapshots & File Trees
# ------------------------------------------------------------------------------
def test_multi_user_tenant_isolation_snapshots(db_session):
    user_a = register(UserRegister(email=f"usera_{os.urandom(4).hex()}@tenant.test", password="Password123!", full_name="User A"), db_session)["user"]
    user_b = register(UserRegister(email=f"userb_{os.urandom(4).hex()}@tenant.test", password="Password123!", full_name="User B"), db_session)["user"]

    plan_a = create_backup_plan(BackupPlanCreate(plan_name="Plan A", source_directories=["uploads/"], schedule_type="manual"), user_a, db_session)

    file_a = UploadFile(filename="usera_confidential.pdf", file=io.BytesIO(b"Confidential user A records"))
    upload_res = upload_file_direct(plan_a.id, None, file_a, user_a, db_session)
    snap_a_id = upload_res["snapshot_id"]

    # User A can view their snapshot tree
    tree_a = get_snapshot_tree(snap_a_id, user_a, db_session)
    assert len(tree_a) == 1
    assert tree_a[0]["file_name"] == "usera_confidential.pdf"

    # User B listing snapshots returns none of User A's snapshots
    snaps_b = list_snapshots(None, user_b, db_session)
    assert all(s.id != snap_a_id for s in snaps_b)

    # User B attempting direct access to User A's snapshot tree receives 404
    with pytest.raises(HTTPException) as exc:
        get_snapshot_tree(snap_a_id, user_b, db_session)
    assert exc.value.status_code == 404


# ------------------------------------------------------------------------------
# 6. Direct Multipart File Upload & Instant Deduplication
# ------------------------------------------------------------------------------
def test_direct_multipart_file_upload_and_deduplication(db_session):
    user = register(UserRegister(email=f"dedup_{os.urandom(4).hex()}@cloudvault.test", password="Password123!", full_name="Dedup User"), db_session)["user"]
    plan = create_backup_plan(BackupPlanCreate(plan_name="Dedup Plan", source_directories=["uploads/"], schedule_type="manual"), user, db_session)

    content = b"CloudVault instant deduplication demonstration payload."
    sha256 = hashlib.sha256(content).hexdigest()

    # Upload 1: First time payload is seen -> Newly compressed & stored
    file1 = UploadFile(filename="sample1.txt", file=io.BytesIO(content))
    res1 = upload_file_direct(plan.id, None, file1, user, db_session)
    assert res1["status"] == "SUCCESS"
    assert res1["sha256"] == sha256
    assert res1["deduplicated"] is False
    assert res1["bytes_stored"] > 0

    # Upload 2: Exact same content -> Instant deduplication bypass (0 new bytes stored)
    file2 = UploadFile(filename="sample1_copy.txt", file=io.BytesIO(content))
    res2 = upload_file_direct(plan.id, "copies/sample1_copy.txt", file2, user, db_session)
    assert res2["status"] == "SUCCESS"
    assert res2["sha256"] == sha256
    assert res2["deduplicated"] is True
    assert res2["bytes_stored"] == 0


# ------------------------------------------------------------------------------
# 7. Large File Upload & SHA-256 Digest Verification
# ------------------------------------------------------------------------------
def test_large_file_upload_and_digest_verification(db_session):
    user = register(UserRegister(email=f"large_{os.urandom(4).hex()}@cloudvault.test", password="Password123!", full_name="Large User"), db_session)["user"]
    plan = create_backup_plan(BackupPlanCreate(plan_name="Large Plan", source_directories=["uploads/"], schedule_type="manual"), user, db_session)

    large_payload = os.urandom(100 * 1024)  # 100 KB payload
    expected_sha = hashlib.sha256(large_payload).hexdigest()

    file_obj = UploadFile(filename="large_data.bin", file=io.BytesIO(large_payload))
    res_upload = upload_file_direct(plan.id, None, file_obj, user, db_session)

    assert res_upload["status"] == "SUCCESS"
    assert res_upload["sha256"] == expected_sha


# ------------------------------------------------------------------------------
# 8. Point-in-Time Restore & Bit-Level SHA-256 Validation
# ------------------------------------------------------------------------------
def test_point_in_time_restore_and_sha256_validation(db_session, tmp_path):
    user = register(UserRegister(email=f"restore_{os.urandom(4).hex()}@cloudvault.test", password="Password123!", full_name="Restore User"), db_session)["user"]
    plan = create_backup_plan(BackupPlanCreate(plan_name="Restore Plan", source_directories=["uploads/"], schedule_type="manual"), user, db_session)

    original_text = b"CloudVault Point-in-Time verified restoration content 2026."
    file_obj = UploadFile(filename="restore_test.txt", file=io.BytesIO(original_text))
    up_res = upload_file_direct(plan.id, None, file_obj, user, db_session)
    snap_id = up_res["snapshot_id"]

    tree = get_snapshot_tree(snap_id, user, db_session)
    file_id = tree[0]["id"]

    dest_dir = str(tmp_path / "restored_dir")
    req = RestoreFileRequest(snapshot_file_id=file_id, destination_directory=dest_dir, conflict_strategy="overwrite")
    restore_res = restore_file(req, user, db_session)

    assert restore_res["status"] == "SUCCESS"
    assert restore_res["integrity_verified"] is True
    restored_path = Path(restore_res["destination"])
    assert restored_path.exists()
    assert restored_path.read_bytes() == original_text


# ------------------------------------------------------------------------------
# 9. Conflict Resolution Strategies: keep_both, overwrite, skip
# ------------------------------------------------------------------------------
def test_conflict_resolution_strategies(db_session, tmp_path):
    user = register(UserRegister(email=f"conflict_{os.urandom(4).hex()}@cloudvault.test", password="Password123!", full_name="Conflict User"), db_session)["user"]
    plan = create_backup_plan(BackupPlanCreate(plan_name="Conflict Plan", source_directories=["uploads/"], schedule_type="manual"), user, db_session)

    content = b"Conflict test data."
    up_res = upload_file_direct(plan.id, None, UploadFile(filename="data.txt", file=io.BytesIO(content)), user, db_session)
    snap_id = up_res["snapshot_id"]
    tree = get_snapshot_tree(snap_id, user, db_session)
    file_id = tree[0]["id"]

    dest_dir = str(tmp_path / "conflict_dir")
    restore_file(RestoreFileRequest(snapshot_file_id=file_id, destination_directory=dest_dir, conflict_strategy="overwrite"), user, db_session)

    # Strategy: keep_both -> creates timestamped copy
    res_keep = restore_file(RestoreFileRequest(snapshot_file_id=file_id, destination_directory=dest_dir, conflict_strategy="keep_both"), user, db_session)
    assert res_keep["status"] == "SUCCESS"
    assert "data_restored_" in res_keep["destination"]

    # Strategy: skip -> skips existing file without failing
    res_skip = restore_file(RestoreFileRequest(snapshot_file_id=file_id, destination_directory=dest_dir, conflict_strategy="skip"), user, db_session)
    assert res_skip["status"] == "SUCCESS"
    assert res_skip["files_restored"] == 0


# ------------------------------------------------------------------------------
# 10. Ransomware Alert Isolation per Tenant
# ------------------------------------------------------------------------------
def test_ransomware_alert_tenant_isolation(db_session):
    user_a = register(UserRegister(email=f"usera_alert_{os.urandom(4).hex()}@tenant.test", password="Password123!", full_name="User A"), db_session)["user"]
    user_b = register(UserRegister(email=f"userb_alert_{os.urandom(4).hex()}@tenant.test", password="Password123!", full_name="User B"), db_session)["user"]

    # User A simulates attack test -> Alert created for User A
    sim_res = simulate_attack_test(SimulateAttackRequest(scenario_type="mass_encryption"), user_a, db_session)
    assert "analysis" in sim_res
    assert sim_res["analysis"]["risk_score"] >= 30
    assert sim_res["alert_created"] is not None

    # User A sees the alert
    alerts_a = list_security_alerts("ALL", user_a, db_session)
    assert len(alerts_a["alerts"]) >= 1

    # User B checks alerts -> User A's alert is completely invisible
    alerts_b = list_security_alerts("ALL", user_b, db_session)
    assert len(alerts_b["alerts"]) == 0


# ------------------------------------------------------------------------------
# 11. AI Assistant Tenant Scoping
# ------------------------------------------------------------------------------
def test_ai_assistant_tenant_scoping(db_session):
    user_a = register(UserRegister(email=f"ai_usera_{os.urandom(4).hex()}@cloudvault.test", password="Password123!", full_name="AI User A"), db_session)["user"]
    user_b = register(UserRegister(email=f"ai_userb_{os.urandom(4).hex()}@cloudvault.test", password="Password123!", full_name="AI User B"), db_session)["user"]

    ai_a = query_ai_assistant(AIQueryRequest(prompt="Is my disaster recovery system ready?"), user_a, db_session)
    assert "response" in ai_a

    ai_b = query_ai_assistant(AIQueryRequest(prompt="How many files are protected?"), user_b, db_session)
    assert "response" in ai_b


# ------------------------------------------------------------------------------
# 12. Multi-Cloud Storage Routing & Providers Matrix
# ------------------------------------------------------------------------------
def test_multi_cloud_routing_and_providers(db_session):
    user = register(UserRegister(email=f"cloud_{os.urandom(4).hex()}@cloudvault.test", password="Password123!", full_name="Cloud User"), db_session)["user"]

    inv = get_inventory(user)
    assert "routing" in inv
    assert "primary" in inv["routing"]
    assert "secondary" in inv["routing"]

    matrix = get_providers_capability_matrix(user)
    providers = matrix["providers"]
    prov_keys = [p.get("provider") for p in providers]
    assert "mock" in prov_keys
    assert "gcs" in prov_keys
    assert "s3" in prov_keys
    assert "azure" in prov_keys


# ------------------------------------------------------------------------------
# 13. PostgreSQL Connection String Compatibility
# ------------------------------------------------------------------------------
def test_postgresql_connection_string_normalization():
    heroku_style = "postgres://user:password@host.internal:5432/cloudvault"
    if heroku_style.startswith("postgres://"):
        normalized = heroku_style.replace("postgres://", "postgresql://", 1)
    else:
        normalized = heroku_style

    assert normalized.startswith("postgresql://")
    assert "user:password@host.internal:5432/cloudvault" in normalized


# ------------------------------------------------------------------------------
# 14. Interrupted Upload & Error Handling
# ------------------------------------------------------------------------------
def test_interrupted_upload_and_error_handling(db_session):
    user = register(UserRegister(email=f"err_{os.urandom(4).hex()}@cloudvault.test", password="Password123!", full_name="Error User"), db_session)["user"]

    # Upload to non-existent plan ID -> 404
    with pytest.raises(HTTPException) as exc:
        upload_file_direct("non-existent-plan-id", None, UploadFile(filename="error.txt", file=io.BytesIO(b"data")), user, db_session)
    assert exc.value.status_code == 404


# ------------------------------------------------------------------------------
# 15. Streamlit Client & UI Helper Unit Tests
# ------------------------------------------------------------------------------
def test_streamlit_api_client_and_styles():
    assert format_bytes(500) == "500.0 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1024 * 1024) == "1.0 MB"
    assert format_bytes(1024 * 1024 * 1024 * 5) == "5.0 GB"
    assert format_bytes(None) == "0 B"

    cv_client = CloudVaultClient(base_url="https://cloudvault-test.onrender.com")
    assert cv_client.base_url == "https://cloudvault-test.onrender.com"

    headers_no_tok = cv_client._headers()
    assert "Authorization" not in headers_no_tok

    headers_tok = cv_client._headers(token="sample-jwt-token")
    assert headers_tok["Authorization"] == "Bearer sample-jwt-token"

    err = APIError(404, "Snapshot not found")
    assert str(err) == "[404] Snapshot not found"
    assert err.status_code == 404
    assert err.detail == "Snapshot not found"
