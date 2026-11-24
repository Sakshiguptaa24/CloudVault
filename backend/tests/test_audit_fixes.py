"""
CloudVault 2.0 — Post-Audit Bug Fix & QA Verification Test Suite
=================================================================
Validates all audit fixes, schema normalizations, and defensive UI
guards across Streamlit views and DemoClient simulation services.
"""

import os
import json
import pytest
from unittest.mock import MagicMock, patch

from streamlit_app.views.backup_plans import normalize_string_list
from streamlit_app.demo_service import DemoClient, get_demo_state


# =====================================================================
# 1. STRING LIST NORMALIZATION TESTS (Backup Plans Fix)
# =====================================================================

def test_normalize_string_list_none_and_empty():
    assert normalize_string_list(None) == []
    assert normalize_string_list("") == []
    assert normalize_string_list("   ") == []
    assert normalize_string_list([]) == []


def test_normalize_string_list_flat_list():
    raw = ["/var/data", "/opt/db"]
    assert normalize_string_list(raw) == ["/var/data", "/opt/db"]


def test_normalize_string_list_nested_list():
    raw = [["/var/data", "/opt/db"], "extra/"]
    assert normalize_string_list(raw) == ["/var/data", "/opt/db", "extra/"]


def test_normalize_string_list_json_encoded_string():
    raw = '["/var/data", "/opt/db"]'
    assert normalize_string_list(raw) == ["/var/data", "/opt/db"]


def test_normalize_string_list_comma_and_newline_separated():
    raw_comma = "docs/, databases/, logs/"
    assert normalize_string_list(raw_comma) == ["docs/", "databases/", "logs/"]

    raw_newline = "docs/\ndatabases/\nlogs/"
    assert normalize_string_list(raw_newline) == ["docs/", "databases/", "logs/"]


def test_normalize_string_list_single_string():
    raw = "Uploads Only"
    assert normalize_string_list(raw) == ["Uploads Only"]


def test_normalize_string_list_reproduce_exact_nested_list_join_error():
    # Exactly reproduces the previous failure where plan source_directories was [['documents/', 'databases/']]
    raw_nested = [["documents/", "databases/"]]
    normalized = normalize_string_list(raw_nested)
    assert normalized == ["documents/", "databases/"]
    # Verify that str.join operates cleanly without TypeError
    joined = ", ".join(normalized)
    assert joined == "documents/, databases/"


def test_normalize_string_list_single_quoted_python_repr():
    # Reproduces Python repr string with single quotes e.g. "['documents/', 'databases/']"
    raw_py_repr = "['documents/', 'databases/']"
    normalized = normalize_string_list(raw_py_repr)
    assert normalized == ["documents/", "databases/"]
    joined = ", ".join(normalized)
    assert joined == "documents/, databases/"


def test_normalize_string_list_deeply_nested_mixed():
    raw_deep = [[[["a"]]], ("b", ["c"]), {"paths": ["d", ("e",)]}]
    normalized = normalize_string_list(raw_deep)
    assert normalized == ["a", "b", "c", "d", "e"]
    assert ", ".join(normalized) == "a, b, c, d, e"


def test_normalize_string_list_semicolons_and_delimiters():
    raw_delims = "docs/; databases/;\nlogs/, extra/"
    normalized = normalize_string_list(raw_delims)
    assert normalized == ["docs/", "databases/", "logs/", "extra/"]


def test_normalize_string_list_mixed_strings_inside_list():
    raw_mixed = ['["json_dir"]', "['py_dir']", "plain_dir"]
    normalized = normalize_string_list(raw_mixed)
    assert normalized == ["json_dir", "py_dir", "plain_dir"]


def test_normalize_string_list_null_like_tokens():
    for token in ("None", "null", "NULL", "[]", "{}", "()", '""', "''"):
        assert normalize_string_list(token) == []


def test_standard_production_vault_plan_render_safe():
    state = get_demo_state()
    plan = next((p for p in state.plans if "Standard Production Vault" in p.get("plan_name", "")), state.plans[0])
    srcs = [str(s) for s in normalize_string_list(plan.get("source_directories")) if str(s).strip()]
    excls = [str(e) for e in normalize_string_list(plan.get("exclusion_patterns")) if str(e).strip()]
    # Must join without raising TypeError: sequence item 0: expected str instance, list found
    joined_srcs = ", ".join(srcs) if srcs else "Uploads Only"
    joined_excls = ", ".join(excls) if excls else "None"
    assert joined_srcs == "documents/, databases/"
    assert joined_excls == "*.tmp, *.cache"


# =====================================================================
# 2. DEMO CLIENT SCHEMA ALIGNMENT TESTS
# =====================================================================

@pytest.fixture
def demo_client():
    return DemoClient()


def test_demo_client_get_me_schema(demo_client):
    user = demo_client.get_me("test-token")
    assert "id" in user
    assert "email" in user
    assert "quota_bytes" in user
    assert "used_bytes" in user
    assert user["used_bytes"] > 0


def test_demo_client_trigger_backup_schema(demo_client):
    res = demo_client.trigger_backup("test-token", "plan-demo-001")
    assert res["status"] == "SUCCESS"
    assert "job_id" in res
    assert "snapshot_name" in res
    assert "files_scanned" in res
    assert "files_uploaded" in res
    assert "bytes_uploaded" in res
    assert "files_deduplicated" in res
    assert "bytes_deduplicated" in res
    assert "duration_seconds" in res


def test_demo_client_get_storage_stats_dual_keys(demo_client):
    stats = demo_client.get_storage_stats("test-token")
    # Verify primary keys
    assert "total_files" in stats
    assert "total_files_protected" in stats
    assert stats["total_files"] == stats["total_files_protected"]

    # Verify deduplication keys
    assert "deduplicated_bytes" in stats
    assert "bytes_saved_deduplication" in stats
    assert stats["deduplicated_bytes"] == stats["bytes_saved_deduplication"]

    # Verify ratio keys
    assert "deduplication_ratio" in stats
    assert "savings_percentage" in stats
    assert stats["deduplication_ratio"] == stats["savings_percentage"]


def test_demo_client_get_deleted_files_schema(demo_client):
    deleted = demo_client.get_deleted_files("test-token", "plan-demo-001")
    assert isinstance(deleted, list)
    assert len(deleted) > 0
    assert "last_seen_snapshot_name" in deleted[0]
    assert deleted[0]["last_seen_snapshot_name"] == "Mid-Week Ledger Snapshot"


def test_demo_client_run_dr_drill_schema(demo_client):
    res = demo_client.run_dr_drill("test-token")
    assert res["status"] == "SUCCESS"
    assert "rto_seconds" in res
    assert "rto_measured_sec" in res
    assert "verified_files" in res
    assert res["verified_files"] > 0


def test_demo_client_list_audit_logs_dual_keys(demo_client):
    audit_data = demo_client.list_audit_logs("test-token")
    assert "logs" in audit_data
    assert "audit_logs" in audit_data
    assert audit_data["logs"] == audit_data["audit_logs"]


def test_demo_client_verify_audit_trail_schema(demo_client):
    ver = demo_client.verify_audit_trail("test-token")
    assert ver["valid"] is True
    assert ver["status"] == "VALID"
    assert "verified_blocks" in ver
    assert ver["verified_blocks"] > 0


def test_demo_client_crypto_status_and_rotation(demo_client):
    crypto = demo_client.get_crypto_status("test-token")
    assert crypto["algorithm"] == "AES-256-GCM"
    assert "key_version" in crypto
    assert "encrypted_objects_count" in crypto
    assert "encryption_ratio_percent" in crypto

    rot = demo_client.rotate_crypto_key("test-token")
    assert rot["status"] == "SUCCESS"
    assert rot["new_key_version"] == 2


def test_demo_client_get_analytics_overview_cost_comparison(demo_client):
    ov = demo_client.get_analytics_overview("test-token")
    assert "cost_comparison" in ov
    costs = ov["cost_comparison"]
    assert "monthly_savings_usd" in costs
    assert costs["monthly_savings_usd"] > 0
    assert "aws_s3_estimate_usd" in costs
    assert "gcp_standard_estimate_usd" in costs


def test_demo_client_get_large_files_rich_schema(demo_client):
    large_files = demo_client.get_large_files("test-token")
    assert len(large_files) > 0
    first = large_files[0]
    assert "path" in first
    assert "relative_path" in first
    assert "file_name" in first
    assert "size_bytes" in first
    assert "file_size" in first
    assert first["size_bytes"] == first["file_size"]


def test_demo_client_get_weekly_report_markdown(demo_client):
    rep = demo_client.get_weekly_report("test-token")
    assert "markdown" in rep
    assert "# CloudVault Weekly Executive Protection Report" in rep["markdown"]


# =====================================================================
# 3. AUDIT CHAIN INTEGRITY & DEFENSIVE MAPPING TESTS
# =====================================================================

def test_demo_state_audit_chain_dual_fields():
    state = get_demo_state()
    for block in state.audit_chain:
        assert "created_at" in block
        assert "timestamp" in block
        assert "action" in block
        assert "event_type" in block
        assert "current_hash" in block
        assert "block_hash" in block


def test_demo_state_jobs_telemetry_fields():
    state = get_demo_state()
    for job in state.jobs:
        assert "trigger_type" in job
        assert "files_scanned" in job
        assert "files_uploaded" in job
        assert "files_deduplicated" in job
        assert "duration_seconds" in job
