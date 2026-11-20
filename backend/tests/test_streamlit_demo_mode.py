"""
CloudVault 2.0 — Streamlit Demo Mode Test Suite
================================================
Verifies that CloudVault's dedicated public demonstration mode is completely
self-contained, zero-cost, air-gapped from production databases and cloud
providers, securely limits uploads to 5 MB, calculates real SHA-256 digests,
demonstrates CAS deduplication live, and preserves production mode untouched.
"""

import os
import sys
import time
import hashlib
from unittest.mock import patch, MagicMock
import pytest

from streamlit_app.demo_service import (
    is_demo_mode,
    calculate_shannon_entropy,
    sanitize_filename,
    DemoClient,
    get_demo_state,
    MAX_DEMO_UPLOAD_BYTES,
    PROHIBITED_EXTENSIONS
)
from streamlit_app.api_client import (
    CloudVaultClient,
    APIError,
    ConfigurationError,
    resolve_backend_url
)


# =====================================================================
# 1. DEMO MODE DETECTION & PRODUCTION ISOLATION
# =====================================================================

def test_is_demo_mode_detection():
    # 1. Explicit env var true
    with patch.dict(os.environ, {"CLOUDVAULT_DEMO_MODE": "true"}):
        assert is_demo_mode() is True

    with patch.dict(os.environ, {"CLOUDVAULT_DEMO_MODE": "1"}):
        assert is_demo_mode() is True

    # 2. Explicit env var false
    with patch.dict(os.environ, {"CLOUDVAULT_DEMO_MODE": "false"}):
        assert is_demo_mode() is False

    # 3. Production mode NEVER silently defaults to demo mode
    with patch.dict(os.environ, {"ENVIRONMENT": "production", "CLOUDVAULT_DEMO_MODE": ""}, clear=True):
        with patch.dict(sys.modules, {"streamlit": None}):
            assert is_demo_mode() is False

    # 4. Production mode with explicit demo flag enabled
    with patch.dict(os.environ, {"ENVIRONMENT": "production", "CLOUDVAULT_DEMO_MODE": "true"}):
        assert is_demo_mode() is True

    # 5. Non-production without BACKEND_API_URL auto-activates demo mode
    with patch.dict(os.environ, {"ENVIRONMENT": "development"}, clear=True):
        with patch.dict(sys.modules, {"streamlit": None}):
            assert is_demo_mode() is True


def test_production_mode_remains_strictly_enforced():
    """Ensure production mode without demo mode rejects invalid configs as before."""
    with patch.dict(os.environ, {}, clear=True):
        with patch.dict(sys.modules, {"streamlit": None}):
            # Missing backend URL in production raises ConfigurationError
            with pytest.raises(ConfigurationError, match="Production mode detected"):
                resolve_backend_url(None, environment="production")

            # Insecure http URL in production raises ConfigurationError
            with pytest.raises(ConfigurationError, match="requires secure HTTPS protocol"):
                resolve_backend_url("http://insecure-api.render.com", environment="production")

            # Localhost in production raises ConfigurationError
            with pytest.raises(ConfigurationError, match="cannot use localhost"):
                resolve_backend_url("https://localhost:8000", environment="production")


# =====================================================================
# 2. ZERO-COST STARTUP WITHOUT BACKEND, POSTGRESQL OR CLOUD CREDS
# =====================================================================

def test_demo_client_startup_without_backend():
    client = CloudVaultClient(demo_mode=True)
    assert client.demo_mode is True
    assert client.base_url == "demo://cloudvault.internal"

    health = client.health_check()
    assert health["status"] == "healthy"
    assert health["demo_mode"] is True
    assert "2.0.0-demo" in health["version"]


def test_demo_mode_without_postgresql_or_cloud_credentials():
    """Verify demo mode operates with zero credentials or cloud configs."""
    with patch.dict(os.environ, {}, clear=True):
        client = DemoClient()
        inv = client.get_storage_inventory("demo-token")
        assert inv["demo_mode"] is True
        assert inv["failover_enabled"] is True

        matrix = client.get_providers_matrix("demo-token")
        assert "Google Cloud Storage" in matrix["primary"]
        assert "Amazon Web Services S3" in matrix["failover"]
        assert "Microsoft Azure Blob" in matrix["archive"]


# =====================================================================
# 3. PUBLIC ACCESS WITHOUT LOGIN & SYNTHETIC DATA
# =====================================================================

def test_public_access_and_synthetic_profile():
    client = DemoClient()
    user = client.get_me("any-token")
    assert user["full_name"] == "Demo Evaluator"
    assert user["is_demo_mode"] is True
    assert user["quota_bytes"] == 5 * 1024 * 1024 * 1024  # 5 GB demo quota


def test_synthetic_dashboard_and_dr_telemetry():
    client = DemoClient()
    stats = client.get_storage_stats("demo-token")
    assert stats["total_files"] >= 14
    assert stats["total_snapshots"] >= 6
    assert stats["deduplication_ratio"] >= 40.0
    assert stats["demo_mode"] is True

    health = client.get_health_score("demo-token")
    assert health["overall_score"] >= 90
    assert health["status"] == "HEALTHY"

    dr = client.get_dr_metrics("demo-token")
    assert dr["readiness_score"] >= 95
    assert dr["rto_seconds"] < 5.0
    assert dr["rpo_minutes"] <= 15


# =====================================================================
# 4. FILE UPLOADS, RESTRICTIONS & SANITIZATION
# =====================================================================

def test_upload_size_limit_rejection():
    client = DemoClient()
    # 5 MB + 1 KB payload
    oversized = b"X" * (MAX_DEMO_UPLOAD_BYTES + 1024)

    with pytest.raises(APIError) as exc_info:
        client.upload_file_direct(
            token="demo-token",
            plan_id="plan-demo-001",
            filename="large_dataset.csv",
            file_bytes=oversized
        )
    assert exc_info.value.status_code == 413
    assert "exceeds demo maximum limit" in exc_info.value.detail


def test_prohibited_executable_extension_rejection():
    client = DemoClient()
    dangerous_file = b"MZ\x90\x00\x03\x00\x00\x00"  # mock executable header

    for ext in (".exe", ".dll", ".bat", ".cmd", ".sh", ".ps1", ".msi"):
        with pytest.raises(APIError) as exc_info:
            client.upload_file_direct(
                token="demo-token",
                plan_id="plan-demo-001",
                filename=f"malicious_payload{ext}",
                file_bytes=dangerous_file
            )
        assert exc_info.value.status_code == 400
        assert "Prohibited file type" in exc_info.value.detail


def test_filename_sanitization():
    # Path traversal patterns
    assert sanitize_filename("../../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\windows\\system32\\cmd.exe") == "cmd.exe"
    assert sanitize_filename("normal_file.pdf") == "normal_file.pdf"
    assert sanitize_filename("folder/subfolder/data.json") == "data.json"


# =====================================================================
# 5. SHA-256 CALCULATION & DEDUPLICATION DEMO
# =====================================================================

def test_sha256_calculation_and_deduplication():
    client = DemoClient()
    content = b"CloudVault 2.0 Unique Ingestion Content for Demo Verification - 2026"
    expected_sha = hashlib.sha256(content).hexdigest()

    # First upload: New file, not deduplicated
    res1 = client.upload_file_direct(
        token="demo-token",
        plan_id="plan-demo-001",
        filename="unique_report_v1.txt",
        file_bytes=content
    )
    assert res1["sha256"] == expected_sha
    assert res1["deduplicated"] is False
    assert res1["demo_mode"] is True

    # Second upload with identical content: Deduplication hit!
    res2 = client.upload_file_direct(
        token="demo-token",
        plan_id="plan-demo-001",
        filename="copy_of_unique_report.txt",
        file_bytes=content
    )
    assert res2["sha256"] == expected_sha
    assert res2["deduplicated"] is True  # 100% Deduplicated!


# =====================================================================
# 6. RESTORATION & BIT-LEVEL INTEGRITY VERIFICATION
# =====================================================================

def test_file_restoration_integrity():
    client = DemoClient()
    content = b"High-value confidential ledger data for bit-level restoration check"
    expected_sha = hashlib.sha256(content).hexdigest()

    # Upload file
    upload_res = client.upload_file_direct(
        token="demo-token",
        plan_id="plan-demo-001",
        filename="financial_ledger.dat",
        file_bytes=content
    )
    assert upload_res["sha256"] == expected_sha

    # Retrieve file from snapshots
    tree = client.get_snapshot_tree("demo-token", upload_res["snapshot_id"])
    target_file = next(f for f in tree if f["sha256_hash"] == expected_sha)

    # Restore file
    restore_res = client.restore_file(
        token="demo-token",
        snapshot_file_id=target_file["id"],
        destination_directory="restored/demo_vault",
        conflict_strategy="keep_both"
    )
    assert restore_res["status"] == "RESTORED"
    assert restore_res["integrity_verified"] is True
    assert restore_res["original_sha256"] == restore_res["restored_sha256"] == expected_sha
    assert restore_res["file_bytes"] == content


# =====================================================================
# 7. SHANNON ENTROPY & ANOMALY HEURISTICS
# =====================================================================

def test_shannon_entropy_calculation():
    # Plain English text (low entropy ~ 3.5 - 4.5)
    english_text = b"CloudVault 2.0 provides continuous zero-trust backup and recovery for cloud enterprise workloads."
    h_low = calculate_shannon_entropy(english_text)
    assert 3.0 < h_low < 5.0

    # High randomness pseudo-ciphertext (high entropy > 7.50)
    high_random = bytes([i % 256 for i in range(1024)])
    h_high = calculate_shannon_entropy(high_random)
    assert h_high >= 7.80


# =====================================================================
# 8. OFFLINE AI ASSISTANT (SEMANTIC COPILOT)
# =====================================================================

def test_ai_copilot_semantic_queries():
    client = DemoClient()

    # Query DR metrics
    res_dr = client.query_ai_assistant("demo-token", "What is my current RTO and RPO?")
    assert "Disaster Recovery Status" in res_dr["response"]
    assert "2.4 seconds" in res_dr["response"]

    # Query Deduplication
    res_dedup = client.query_ai_assistant("demo-token", "Explain my deduplication storage savings")
    assert "Storage & Deduplication Analysis" in res_dedup["response"]
    assert "reduction" in res_dedup["response"]

    # Privileged action returns HMAC confirmation card
    res_act = client.query_ai_assistant("demo-token", "Trigger an immediate backup")
    assert res_act["action_card"] is not None
    assert "TRIGGER_BACKUP_PLAN" in res_act["action_card"]["action_type"]

    # Confirm privileged action
    conf = client.confirm_ai_action("demo-token", res_act["action_card"]["confirmation_token"])
    assert conf["status"] == "EXECUTED"


# =====================================================================
# 9. DEMO DATA ISOLATION FROM REAL LOCAL DATABASE
# =====================================================================

def test_demo_data_isolation():
    db_path = "data/cloudvault.db"
    if os.path.exists(db_path):
        mtime_before = os.path.getmtime(db_path)
        size_before = os.path.getsize(db_path)

        # Execute demo uploads, restores, and queries
        client = DemoClient()
        client.upload_file_direct(
            token="demo-token",
            plan_id="plan-demo-001",
            filename="sandbox_test.txt",
            file_bytes=b"Sandbox test isolated payload"
        )
        client.get_storage_stats("demo-token")

        # Verify real database file was not touched or opened
        assert os.path.getmtime(db_path) == mtime_before
        assert os.path.getsize(db_path) == size_before
