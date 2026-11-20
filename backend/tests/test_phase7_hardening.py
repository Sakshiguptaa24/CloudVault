import io
import os
import sys
import time
import pytest
import requests
from unittest.mock import MagicMock, patch
from pathlib import Path
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.app.config import Settings, KNOWN_INSECURE_DEFAULT_SECRET
from backend.app.models import User, BackupPlan, Snapshot, StorageObject, SnapshotFile
from backend.app.schemas import UserRegister, UserLogin
from backend.app.routers.auth import register, login
from backend.app.routers.backups import upload_file_direct
from backend.app.routers.events import sse_events_stream
from backend.app.services.crypto_service import (
    envelope_encrypt_payload, envelope_decrypt_payload, derive_user_kek, derive_object_dek,
    encrypt_payload_aes_gcm
)
from backend.app.services.backup_service import compress_payload, calculate_bytes_sha256
from backend.app.services.restore_service import restore_file_by_id, restore_single_snapshot_file
from backend.app.services.rate_limiter import (
    SlidingWindowRateLimiter, LoginRateLimiter, RegisterRateLimiter, get_client_ip
)
from backend.app.migrations import (
    run_migrations, generate_postgres_migration_sql, is_migration_applied, MIGRATION_VERSION
)
from streamlit_app.api_client import (
    CloudVaultClient, APIError, AuthenticationExpiredError, ConfigurationError, resolve_backend_url
)
from streamlit_app.session import handle_auth_expired


# =====================================================================
# 1. FIX A: STREAMLIT SECRETS & BACKEND RESOLUTION
# =====================================================================

def test_resolve_backend_url_precedence():
    # 1. Explicit constructor URL takes highest precedence
    url = resolve_backend_url("https://explicit-api.production.internal/")
    assert url == "https://explicit-api.production.internal"  # Trailing slash stripped

    # 2. Streamlit secrets resolution
    mock_st = MagicMock()
    mock_st.secrets = {"BACKEND_API_URL": "https://streamlit-secrets-api.domain.com/"}
    with patch.dict(sys.modules, {"streamlit": mock_st}):
        url = resolve_backend_url(None, environment="production")
        assert url == "https://streamlit-secrets-api.domain.com"

    # 3. Environment variable resolution
    with patch.dict(os.environ, {"BACKEND_API_URL": "https://env-api.domain.com/"}):
        with patch.dict(sys.modules, {"streamlit": None}):
            url = resolve_backend_url(None, environment="production")
            assert url == "https://env-api.domain.com"

    # 4. Local development fallback
    with patch.dict(os.environ, {}, clear=True):
        with patch.dict(sys.modules, {"streamlit": None}):
            url = resolve_backend_url(None, environment="development")
            assert url == "http://localhost:8000"


def test_resolve_backend_url_production_enforcement():
    # Production rejects missing backend URL
    with patch.dict(os.environ, {}, clear=True):
        with patch.dict(sys.modules, {"streamlit": None}):
            with pytest.raises(ConfigurationError, match="Production mode detected"):
                resolve_backend_url(None, environment="production")

    # Production rejects insecure http://
    with pytest.raises(ConfigurationError, match="requires secure HTTPS protocol"):
        resolve_backend_url("http://insecure-api.render.com", environment="production")

    # Production rejects localhost / 127.0.0.1
    with pytest.raises(ConfigurationError, match="cannot use localhost"):
        resolve_backend_url("https://localhost:8000", environment="production")


# =====================================================================
# 2. FIX B: PRODUCTION STORAGE DURABILITY
# =====================================================================

def test_production_storage_durability_validation():
    # Development mode allows mock storage
    dev_settings = Settings(ENVIRONMENT="development", STORAGE_PROVIDER="mock")
    dev_settings.validate_storage_configuration()  # Must not raise

    # Production mode rejects mock storage
    prod_mock = Settings(ENVIRONMENT="production", STORAGE_PROVIDER="mock")
    with pytest.raises(RuntimeError, match="Production durability violation: STORAGE_PROVIDER cannot be 'mock'"):
        prod_mock.validate_storage_configuration()

    # Production mode rejects missing bucket/container
    prod_gcs = Settings(ENVIRONMENT="production", STORAGE_PROVIDER="gcs", GCS_BUCKET_NAME="")
    with pytest.raises(RuntimeError, match="missing required GCS_BUCKET_NAME"):
        prod_gcs.validate_storage_configuration()

    prod_s3 = Settings(ENVIRONMENT="production", STORAGE_PROVIDER="s3", AWS_S3_BUCKET="")
    with pytest.raises(RuntimeError, match="missing required AWS_S3_BUCKET"):
        prod_s3.validate_storage_configuration()

    # Production mode rejects failover to mock
    prod_failover = Settings(
        ENVIRONMENT="production",
        STORAGE_PROVIDER="s3",
        AWS_S3_BUCKET="my-vault-bucket",
        STORAGE_FAILOVER_ENABLED=True,
        STORAGE_SECONDARY_PROVIDER="mock"
    )
    with pytest.raises(RuntimeError, match="Production failover violation"):
        prod_failover.validate_storage_configuration()

    # Production with valid cloud configuration passes
    prod_valid = Settings(
        ENVIRONMENT="production",
        STORAGE_PROVIDER="s3",
        AWS_S3_BUCKET="my-vault-bucket",
        STORAGE_FAILOVER_ENABLED=False
    )
    prod_valid.validate_storage_configuration()


# =====================================================================
# 3. FIX C: JWT SECRET VALIDATION
# =====================================================================

def test_production_jwt_secret_validation():
    # Development mode accepts default placeholder
    dev_settings = Settings(ENVIRONMENT="development", SECRET_KEY=KNOWN_INSECURE_DEFAULT_SECRET)
    dev_settings.validate_security_configuration()

    # Production mode rejects default placeholder
    prod_default = Settings(ENVIRONMENT="production", SECRET_KEY=KNOWN_INSECURE_DEFAULT_SECRET)
    with pytest.raises(RuntimeError, match="cannot use the default placeholder"):
        prod_default.validate_security_configuration()

    # Production mode rejects short secrets
    prod_short = Settings(ENVIRONMENT="production", SECRET_KEY="short-secret-123")
    with pytest.raises(RuntimeError, match="must be at least 32 characters long"):
        prod_short.validate_security_configuration()

    # Production mode validates strong random secret (and never leaks secret value in error)
    strong_key = "a" * 48
    prod_valid = Settings(
        ENVIRONMENT="production",
        SECRET_KEY=strong_key,
        ALLOWED_ORIGINS="https://cloudvault.app"
    )
    prod_valid.validate_security_configuration()


# =====================================================================
# 4. FIX D: PRODUCTION CORS RESTRICTIONS
# =====================================================================

def test_production_cors_validation():
    # Production rejects wildcard '*'
    prod_star = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="a" * 48,
        ALLOWED_ORIGINS="*"
    )
    with pytest.raises(RuntimeError, match="cannot be empty or wildcard"):
        prod_star.validate_security_configuration()

    # Production rejects insecure http://
    prod_http = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="a" * 48,
        ALLOWED_ORIGINS="http://my-insecure-site.com"
    )
    with pytest.raises(RuntimeError, match="Origin must use secure HTTPS protocol"):
        prod_http.validate_security_configuration()

    # Production accepts multiple valid HTTPS domains
    prod_multi = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="a" * 48,
        ALLOWED_ORIGINS="https://vault.company.com, https://backup.company.com"
    )
    prod_multi.validate_security_configuration()


# =====================================================================
# 5. FIX E: DIRECT WEB UPLOAD ENVELOPE ENCRYPTION & INTEGRITY
# =====================================================================

def test_direct_web_upload_envelope_encryption(db_session):
    from fastapi import UploadFile
    from backend.app.auth import get_password_hash

    test_user = User(
        email="direct_upload_p7@university.edu",
        password_hash=get_password_hash("ValidPass123!"),
        full_name="Phase 7 Test User",
        quota_bytes=5 * 1024 * 1024 * 1024,
        used_bytes=0,
        is_active=True,
        encryption_salt="abcdef0123456789",
        current_key_version=1
    )
    db_session.add(test_user)
    db_session.commit()
    db_session.refresh(test_user)

    # 1. Create a backup plan with encryption enabled
    plan = BackupPlan(
        user_id=test_user.id,
        plan_name="Encrypted Web Upload Plan",
        source_directories="[]",
        retention_days=30,
        compression_algo="gzip",
        encryption_enabled=True
    )
    db_session.add(plan)
    db_session.commit()

    # 2. Upload file directly via upload_file_direct
    file_bytes = b"CONFIDENTIAL_ENTERPRISE_DATA_PHASE_7_VERIFICATION_PAYLOAD"
    upload = UploadFile(filename="confidential_report.docx", file=io.BytesIO(file_bytes))

    result = upload_file_direct(
        plan_id=plan.id,
        relative_path="docs/confidential_report.docx",
        file=upload,
        current_user=test_user,
        db=db_session
    )

    assert result["status"] == "SUCCESS"
    assert result["deduplicated"] is False
    assert result["sha256"] == calculate_bytes_sha256(file_bytes)

    # 3. Verify StorageObject metadata in DB
    obj = db_session.query(StorageObject).filter(StorageObject.sha256_hash == result["sha256"]).first()
    assert obj is not None
    assert obj.is_encrypted is True
    assert obj.encryption_algo == "AES-256-GCM"
    assert obj.encryption_nonce is not None
    assert obj.encrypted_dek is not None
    assert obj.dek_nonce is not None
    assert obj.key_version == 1
    assert obj.aad_tag == f"{test_user.id}:{result['sha256']}:1"

    # 4. Verify stored bytes are ciphertext, not plaintext
    from backend.app.storage import get_storage_provider
    storage = get_storage_provider()
    raw_stored_bytes = storage.download_bytes(obj.storage_path)
    assert raw_stored_bytes != file_bytes
    assert b"CONFIDENTIAL_ENTERPRISE_DATA" not in raw_stored_bytes

    # 5. Verify Restore: authenticated decryption and SHA-256 verification
    snap_file = db_session.query(SnapshotFile).filter(SnapshotFile.snapshot_id == result["snapshot_id"]).first()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp_dest:
        restore_res = restore_file_by_id(
            snapshot_file_id=snap_file.id,
            destination_dir=tmp_dest,
            conflict_strategy="overwrite",
            db=db_session,
            storage=storage,
            user_id=test_user.id
        )
        assert restore_res["status"] == "RESTORED"
        assert restore_res["sha256_verified"] is True
        assert Path(restore_res["path"]).read_bytes() == file_bytes

    # 6. Verify Deduplication: duplicate upload increments ref_count and does not re-encrypt
    dup_upload = UploadFile(filename="confidential_report_copy.docx", file=io.BytesIO(file_bytes))
    dup_result = upload_file_direct(
        plan_id=plan.id,
        relative_path="docs/confidential_report_copy.docx",
        file=dup_upload,
        current_user=test_user,
        db=db_session
    )
    assert dup_result["status"] == "SUCCESS"
    assert dup_result["deduplicated"] is True
    db_session.refresh(obj)
    assert obj.ref_count == 2

    # 7. Path traversal prevention in direct upload
    traversal_upload = UploadFile(filename="exploit.txt", file=io.BytesIO(b"malicious"))
    t_result = upload_file_direct(
        plan_id=plan.id,
        relative_path="../../etc/passwd",
        file=traversal_upload,
        current_user=test_user,
        db=db_session
    )
    t_snap_file = db_session.query(SnapshotFile).filter(SnapshotFile.snapshot_id == t_result["snapshot_id"]).first()
    assert ".." not in t_snap_file.relative_path
    assert not t_snap_file.relative_path.startswith("/")


# =====================================================================
# 6. FIX F: LOGIN & REGISTRATION RATE LIMITING
# =====================================================================

def test_login_rate_limiting():
    limiter = LoginRateLimiter(max_attempts=3, window_seconds=60)
    limiter.clear()

    email = "target_account@university.edu"
    ip = "192.168.1.100"

    # 1. First 2 failures are allowed
    limiter.record_failure(email, ip)
    limiter.check_rate_limit(email, ip)
    limiter.record_failure(email, ip)
    limiter.check_rate_limit(email, ip)

    # 2. 3rd failure reaches max_attempts
    limiter.record_failure(email, ip)
    with pytest.raises(HTTPException) as exc_info:
        limiter.check_rate_limit(email, ip)
    assert exc_info.value.status_code == 429
    assert "Retry-After" in exc_info.value.headers

    # 3. Successful login resets failure counter
    limiter.reset_failures(email, ip)
    limiter.check_rate_limit(email, ip)  # Should now pass freely


def test_registration_rate_limiting():
    limiter = RegisterRateLimiter(max_attempts=3, window_seconds=60)
    limiter.clear()

    ip = "192.168.1.200"

    # Attempts 1, 2, 3 succeed
    limiter.check_and_record(ip, enforce_in_testing=True)
    limiter.check_and_record(ip, enforce_in_testing=True)
    limiter.check_and_record(ip, enforce_in_testing=True)

    # 4th attempt is throttled
    with pytest.raises(HTTPException) as exc_info:
        limiter.check_and_record(ip, enforce_in_testing=True)
    assert exc_info.value.status_code == 429
    assert "Registration rate limit exceeded" in exc_info.value.detail


# =====================================================================
# 7. FIX G: AUTHENTICATE SERVER-SENT EVENTS
# =====================================================================

def test_sse_endpoint_authentication():
    from datetime import timedelta
    from starlette.requests import Request
    from backend.app.auth import create_access_token

    req = Request(scope={"type": "http", "headers": []})

    # 1. Missing token raises 401
    with pytest.raises(HTTPException) as exc1:
        sse_events_stream(request=req, token=None, db=None)
    assert exc1.value.status_code == 401
    assert "Authentication required" in exc1.value.detail

    # 2. Invalid token raises 401
    with pytest.raises(HTTPException) as exc2:
        sse_events_stream(request=req, token="invalid.bogus.jwt", db=None)
    assert exc2.value.status_code == 401
    assert "Invalid or expired" in exc2.value.detail

    # 3. Expired token raises 401
    expired_token = create_access_token({"sub": "user-123"}, expires_delta=timedelta(minutes=-10))
    with pytest.raises(HTTPException) as exc3:
        sse_events_stream(request=req, token=expired_token, db=None)
    assert exc3.value.status_code == 401
    assert "Invalid or expired" in exc3.value.detail

    # 4. Valid token with active user succeeds and returns StreamingResponse
    mock_db = MagicMock()
    mock_user = User(id="user-123", email="user@test.com", is_active=True)
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user

    valid_token = create_access_token({"sub": "user-123", "email": "user@test.com"})
    res = sse_events_stream(request=req, token=valid_token, db=mock_db)
    assert res.status_code == 200
    assert res.media_type == "text/event-stream"

    # 5. Token for deactivated user raises 401
    mock_db_inactive = MagicMock()
    inactive_user = User(id="user-inactive", email="inactive@test.com", is_active=False)
    mock_db_inactive.query.return_value.filter.return_value.first.return_value = inactive_user
    inactive_token = create_access_token({"sub": "user-inactive", "email": "inactive@test.com"})
    with pytest.raises(HTTPException) as exc4:
        sse_events_stream(request=req, token=inactive_token, db=mock_db_inactive)
    assert exc4.value.status_code == 401
    assert "deactivated" in exc4.value.detail


# =====================================================================
# 8. FIX H: POSTGRESQL-COMPATIBLE MIGRATIONS
# =====================================================================

def test_engine_agnostic_migrations(db_session):
    # Run migrations on active engine
    result = run_migrations()
    assert result["status"] == "SUCCESS"
    assert result["migration_version"] == MIGRATION_VERSION

    # Idempotent second run produces no errors
    result2 = run_migrations()
    assert result2["status"] == "SUCCESS"

    # PostgreSQL DDL generation produces valid syntax without SQLite PRAGMAs
    pg_sql = generate_postgres_migration_sql()
    assert "PRAGMA" not in pg_sql
    assert "DO $$ BEGIN" in pg_sql
    assert "schema_migrations" in pg_sql
    assert "TIMESTAMP WITH TIME ZONE" in pg_sql


# =====================================================================
# 9. FIX I & J: STREAMLIT EXPIRED SESSION & COLD START
# =====================================================================

def test_api_client_health_check_cold_start():
    client = CloudVaultClient(base_url="http://localhost:8000")

    # Mock ConnectTimeout (simulates sleeping serverless container)
    with patch("requests.get", side_effect=requests.exceptions.ConnectTimeout):
        res = client.health_check(force=True)
        assert res["status"] == "cold_start"
        assert "spinning up from cold start" in res["message"]

    # Mock ReadTimeout (simulates slow / high-latency backend)
    with patch("requests.get", side_effect=requests.exceptions.ReadTimeout):
        res = client.health_check(force=True)
        assert res["status"] == "slow_response"
        assert "timed out" in res["message"]

    # Mock 401 response raises AuthenticationExpiredError
    mock_resp = MagicMock()
    mock_resp.ok = False
    mock_resp.status_code = 401
    mock_resp.json.return_value = {"detail": "Token has expired"}
    with pytest.raises(AuthenticationExpiredError) as exc_info:
        client._handle_response(mock_resp)
    assert "Token has expired" in str(exc_info.value)


# =====================================================================
# 10. STREAMLIT PAGE SUITE VERIFICATION
# =====================================================================

def test_all_twelve_streamlit_pages_import():
    import ast
    views_dir = Path(__file__).resolve().parent.parent.parent / "streamlit_app" / "views"
    views = [
        "landing", "register", "login", "dashboard",
        "upload_backup", "backup_plans", "snapshots",
        "restore_recovery", "security_center", "ai_assistant",
        "analytics", "settings"
    ]
    assert len(views) == 12
    for view_name in views:
        view_file = views_dir / f"{view_name}.py"
        assert view_file.exists(), f"View file {view_name}.py missing"
        source = view_file.read_text(encoding="utf-8")
        parsed = ast.parse(source, filename=str(view_file))
        func_names = [node.name for node in ast.walk(parsed) if isinstance(node, ast.FunctionDef)]
        assert f"render_{view_name}" in func_names, f"render_{view_name} missing from {view_name}.py"
