"""
CloudVault 2.0 — Dedicated Self-Contained Streamlit Demonstration Engine
========================================================================
Provides zero-cost, zero-configuration, air-gapped demo functionality for
Streamlit Community Cloud. When CLOUDVAULT_DEMO_MODE is active, all views
interact with this in-memory simulation engine without needing:
  - External FastAPI backend server
  - PostgreSQL or SQLite database file access
  - Google Cloud Storage / S3 / Azure cloud credentials
  - External LLM / AI API keys
  - Any cloud spend or billing ($0.00 / ₹0)

All synthetic demo data and temporary visitor uploads are strictly isolated in
the visitor's session state and never touch production user databases.
"""

import os
import sys
import time
import math
import hashlib
import re
from typing import Dict, Any, List, Optional, Tuple

# Safe upload limits for demo safety
MAX_DEMO_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB
PROHIBITED_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".sh", ".vbs", ".ps1",
    ".msi", ".jar", ".scr", ".bin", ".com", ".pif", ".cpl", ".iso"
}


def is_demo_mode() -> bool:
    """
    Determine if CloudVault should run in self-contained Demo Mode.
    Precedence:
      1. Explicit environment variable: CLOUDVAULT_DEMO_MODE=true / 1 / yes
      2. Streamlit Community Cloud secrets: st.secrets["CLOUDVAULT_DEMO_MODE"]
      3. Safety check: If ENVIRONMENT == 'production', NEVER default to demo mode!
      4. Session state override: st.session_state["demo_mode_active"]
      5. Auto-fallback for Streamlit Community Cloud:
         When no BACKEND_API_URL is configured in non-production environments,
         CloudVault automatically defaults to demo mode so visitors can explore
         the app immediately without any configuration errors.
    """
    # 1. Explicit env var
    env_demo = os.getenv("CLOUDVAULT_DEMO_MODE")
    if env_demo is not None:
        return env_demo.strip().lower() in ("true", "1", "yes")

    # 2. Streamlit secrets
    try:
        import streamlit as st
        if hasattr(st, "secrets") and st.secrets is not None:
            if "CLOUDVAULT_DEMO_MODE" in st.secrets:
                return str(st.secrets["CLOUDVAULT_DEMO_MODE"]).strip().lower() in ("true", "1", "yes")
            if "general" in st.secrets and "CLOUDVAULT_DEMO_MODE" in st.secrets["general"]:
                return str(st.secrets["general"]["CLOUDVAULT_DEMO_MODE"]).strip().lower() in ("true", "1", "yes")
    except Exception:
        pass

    # 3. Production safety guard: Production mode must NEVER silently switch to demo mode
    app_env = os.getenv("ENVIRONMENT") or os.getenv("CLOUDVAULT_ENV", "")
    if str(app_env).strip().lower() in ("production", "prod"):
        return False

    # 4. Session state toggle
    try:
        import streamlit as st
        if hasattr(st, "session_state") and "demo_mode_active" in st.session_state:
            return bool(st.session_state["demo_mode_active"])
    except Exception:
        pass

    # 5. Check if BACKEND_API_URL is configured
    backend_url = os.getenv("BACKEND_API_URL")
    try:
        import streamlit as st
        if hasattr(st, "secrets") and st.secrets is not None:
            if "BACKEND_API_URL" in st.secrets:
                backend_url = backend_url or st.secrets["BACKEND_API_URL"]
            elif "general" in st.secrets and "BACKEND_API_URL" in st.secrets["general"]:
                backend_url = backend_url or st.secrets["general"]["BACKEND_API_URL"]
    except Exception:
        pass

    # If backend URL is absent in non-production, activate demo mode
    if not backend_url:
        return True

    return False


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte sequence (in bits/byte: 0.0 to 8.0)."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def sanitize_filename(filename: str) -> str:
    """Strip dangerous characters and directory traversal patterns from filename."""
    name = os.path.basename(filename)
    # Strip null bytes and control chars
    name = re.sub(r'[\x00-\x1f\x7f]', '', name)
    # Strip directory traversal markers
    name = name.replace("..", "").replace("/", "").replace("\\", "").strip()
    return name or "unnamed_sample.dat"


# -----------------------------------------------------------------------------
# Synthetic Demo Baseline Data (Air-Gapped from Real Database)
# -----------------------------------------------------------------------------
SAMPLE_HARMFUL_EXTENSIONS = PROHIBITED_EXTENSIONS

INITIAL_DEMO_FILES = [
    {
        "id": "file-demo-001",
        "relative_path": "finance/2026_q3_financial_audit.pdf",
        "file_size": 348160,
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "modified_at": "2026-11-20T08:15:00Z",
        "entropy": 4.82,
        "is_deleted": False,
        "content": b"%PDF-1.7 CloudVault Sample Financial Audit Report 2026 - All balances verified and reconciled."
    },
    {
        "id": "file-demo-002",
        "relative_path": "customers/enterprise_clients_export.csv",
        "file_size": 1258291,
        "sha256_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
        "modified_at": "2026-11-20T09:30:00Z",
        "entropy": 4.12,
        "is_deleted": False,
        "content": b"client_id,company_name,tier,sla,status\n1,Acme Corp,Enterprise,99.99%,Active\n2,Global Logistics,Tier 1,99.95%,Active\n3,Vertex Cloud,Enterprise,99.99%,Active"
    },
    {
        "id": "file-demo-003",
        "relative_path": "infrastructure/k8s_production_cluster.yaml",
        "file_size": 18432,
        "sha256_hash": "f5e4d3c2b1a09876543210fedcba9876543210fedcba9876543210fedcba9876",
        "modified_at": "2026-11-19T14:22:00Z",
        "entropy": 4.65,
        "is_deleted": False,
        "content": b"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: cloudvault-dr-worker\nspec:\n  replicas: 3\n  template:\n    spec:\n      containers:\n      - name: worker\n        image: cloudvault:latest"
    },
    {
        "id": "file-demo-004",
        "relative_path": "presentations/capstone_cloudvault_overview.pptx",
        "file_size": 4915200,
        "sha256_hash": "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa",
        "modified_at": "2026-11-18T16:45:00Z",
        "entropy": 7.42,
        "is_deleted": False,
        "content": b"CloudVault 2.0 Architectural Defense Presentation - Zero Trust Recovery Platform"
    },
    {
        "id": "file-demo-005",
        "relative_path": "database/users_table_backup.sql",
        "file_size": 819200,
        "sha256_hash": "7766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa9988",
        "modified_at": "2026-11-17T11:10:00Z",
        "entropy": 4.95,
        "is_deleted": False,
        "content": b"-- CloudVault Database Dump (Users Table Snapshot)\nCREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255));\n"
    }
]

INITIAL_DEMO_SNAPSHOTS = [
    {
        "id": "snap-demo-20261120-001",
        "name": "Daily Enterprise Protection Snapshot",
        "created_at": "2026-11-20T08:00:00Z",
        "total_files": 14,
        "total_uncompressed_bytes": 1488977920,  # ~1.38 GB
        "total_stored_bytes": 864026624,         # ~824 MB
        "worm_locked_until": "2026-12-04T08:00:00Z",
        "is_quarantined": False,
        "retention_policy": "standard_30d"
    },
    {
        "id": "snap-demo-20261119-002",
        "name": "Pre-Patch Infrastructure Checkpoint",
        "created_at": "2026-11-19T18:30:00Z",
        "total_files": 12,
        "total_uncompressed_bytes": 1342177280,
        "total_stored_bytes": 817889280,
        "worm_locked_until": "2026-12-03T18:30:00Z",
        "is_quarantined": False,
        "retention_policy": "standard_30d"
    },
    {
        "id": "snap-demo-20261118-001",
        "name": "Mid-Week Ledger Snapshot",
        "created_at": "2026-11-18T12:00:00Z",
        "total_files": 10,
        "total_uncompressed_bytes": 943718400,
        "total_stored_bytes": 681574400,
        "worm_locked_until": "2026-12-02T12:00:00Z",
        "is_quarantined": False,
        "retention_policy": "standard_30d"
    },
    {
        "id": "snap-demo-20261117-003",
        "name": "Synthetic DR Command Center Drill Run",
        "created_at": "2026-11-17T09:15:00Z",
        "total_files": 14,
        "total_uncompressed_bytes": 1488977920,
        "total_stored_bytes": 864026624,
        "worm_locked_until": "2026-12-01T09:15:00Z",
        "is_quarantined": False,
        "retention_policy": "standard_30d"
    },
    {
        "id": "snap-demo-20261116-001",
        "name": "Weekly Baseline Gold Master",
        "created_at": "2026-11-16T00:00:00Z",
        "total_files": 14,
        "total_uncompressed_bytes": 1488977920,
        "total_stored_bytes": 859832320,
        "worm_locked_until": "2026-11-30T00:00:00Z",
        "is_quarantined": False,
        "retention_policy": "standard_30d"
    },
    {
        "id": "snap-demo-20261115-001",
        "name": "Initial Seed Vault Snapshot",
        "created_at": "2026-11-15T06:00:00Z",
        "total_files": 8,
        "total_uncompressed_bytes": 629145600,
        "total_stored_bytes": 471859200,
        "worm_locked_until": "2026-11-29T06:00:00Z",
        "is_quarantined": False,
        "retention_policy": "standard_30d"
    }
]

INITIAL_DEMO_ALERTS = [
    {
        "id": "alert-demo-081",
        "alert_type": "Heuristic Entropy & Extension Anomaly",
        "risk_score": 88,
        "status": "ACTIVE",
        "created_at": "2026-11-20T06:14:22Z",
        "reasons": [
            "Sudden Shannon entropy delta +7.84 on finance/quarterly_projections.xlsx.locked",
            "Monitored ransomware extension matched (.locked)",
            "Burst modification of 18 files within 600ms"
        ],
        "affected_snapshot_ids": ["snap-demo-20261119-002"],
        "recommended_action": "Isolate host, quarantine affected snapshot, and initiate PIT restoration."
    }
]


class DemoState:
    """Manages isolated, in-memory state for the active Streamlit session."""

    def __init__(self):
        self.files = list(INITIAL_DEMO_FILES)
        self.snapshots = list(INITIAL_DEMO_SNAPSHOTS)
        self.alerts = list(INITIAL_DEMO_ALERTS)
        self.plans = [
            {
                "id": "plan-demo-001",
                "plan_name": "Standard Production Vault (Demo)",
                "source_directories": ["documents/", "databases/"],
                "exclusion_patterns": ["*.tmp", "*.cache"],
                "schedule_type": "daily",
                "schedule_expression": "0 2 * * *",
                "retention_days": 30,
                "compression_algo": "gzip"
            }
        ]
        self.jobs = [
            {
                "id": "job-demo-101",
                "plan_name": "Standard Production Vault (Demo)",
                "status": "COMPLETED",
                "started_at": "2026-11-20T08:00:00Z",
                "completed_at": "2026-11-20T08:01:14Z",
                "files_processed": 14,
                "bytes_transferred": 864026624,
                "deduplication_ratio": 42.0
            },
            {
                "id": "job-demo-102",
                "plan_name": "Standard Production Vault (Demo)",
                "status": "COMPLETED",
                "started_at": "2026-11-19T18:30:00Z",
                "completed_at": "2026-11-19T18:31:02Z",
                "files_processed": 12,
                "bytes_transferred": 817889280,
                "deduplication_ratio": 39.1
            }
        ]
        self.audit_chain = [
            {
                "sequence": 1,
                "event_type": "SYSTEM_SEED",
                "actor": "system",
                "details": "Initialized immutable cryptographic hash chain",
                "block_hash": "c8f2a1b3e4d567890123456789abcdef0123456789abcdef0123456789abcdef",
                "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "timestamp": "2026-11-20T07:00:00Z"
            },
            {
                "sequence": 2,
                "event_type": "SNAPSHOT_CREATE",
                "actor": "demo-evaluator",
                "details": "Created immutable point-in-time snapshot snap-demo-20261120-001",
                "block_hash": "e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2",
                "prev_hash": "c8f2a1b3e4d567890123456789abcdef0123456789abcdef0123456789abcdef",
                "timestamp": "2026-11-20T08:00:00Z"
            }
        ]
        # In-memory storage for deduplication tracking
        self.content_by_hash: Dict[str, bytes] = {
            f["sha256_hash"]: f.get("content", b"") for f in self.files
        }
        self.cached_tokens: Dict[str, Dict[str, Any]] = {}


def get_demo_state() -> DemoState:
    """Retrieve or initialize DemoState in Streamlit session state."""
    try:
        import streamlit as st
        if "demo_state" not in st.session_state:
            st.session_state["demo_state"] = DemoState()
        return st.session_state["demo_state"]
    except Exception:
        # Fallback for non-Streamlit unit test execution
        if not hasattr(get_demo_state, "_test_instance"):
            get_demo_state._test_instance = DemoState()
        return get_demo_state._test_instance


# -----------------------------------------------------------------------------
# Demo Client (Drop-in Replacement for CloudVaultClient in Demo Mode)
# -----------------------------------------------------------------------------
class DemoClient:
    """
    Self-contained, in-memory implementation of CloudVaultClient.
    Provides identical method signatures and response schemas for all 12 views,
    ensuring zero-cost demonstration without external backend dependencies.
    """

    def __init__(self, base_url: Optional[str] = None, environment: Optional[str] = None):
        self.base_url = "demo://cloudvault.internal"
        self.environment = "demo"
        self.demo_mode = True

    def _headers(self, token: Optional[str] = None) -> Dict[str, str]:
        return {"Accept": "application/json", "Authorization": f"Bearer {token or 'demo-token'}"}

    # -------------------------------------------------------------
    # System & Health
    # -------------------------------------------------------------
    def health_check(self, timeout: int = 45, force: bool = False) -> Dict[str, Any]:
        return {
            "status": "healthy",
            "storage_provider": "multi-cloud-demo",
            "version": "2.0.0-demo",
            "demo_mode": True,
            "architecture": "Zero-Cost Air-Gapped Simulation",
            "message": "CloudVault 2.0 Interactive Public Demo Engine is fully operational."
        }

    # -------------------------------------------------------------
    # Authentication & Profile
    # -------------------------------------------------------------
    def get_me(self, token: str) -> Dict[str, Any]:
        return {
            "id": "demo-evaluator-001",
            "email": "demo-evaluator@cloudvault.internal",
            "full_name": "Demo Evaluator",
            "role": "evaluator",
            "quota_bytes": 5 * 1024 * 1024 * 1024,  # 5 GB demo quota
            "created_at": "2026-11-20T00:00:00Z",
            "is_demo_mode": True
        }

    def register(self, email: str, password: str, full_name: str) -> Dict[str, Any]:
        return {
            "id": "demo-evaluator-new",
            "email": email,
            "full_name": full_name,
            "message": "Demo user account registered successfully (session-scoped)."
        }

    def login(self, email: str, password: str, mfa_code: Optional[str] = None) -> Dict[str, Any]:
        return {
            "access_token": "demo-session-token-2026",
            "token_type": "bearer",
            "user": {
                "id": "demo-evaluator-001",
                "email": email or "demo-evaluator@cloudvault.internal",
                "full_name": "Demo Evaluator"
            }
        }

    def setup_mfa(self, token: str) -> Dict[str, Any]:
        return {
            "secret": "JBSWY3DPEHPK3PXP",
            "otpauth_url": "otpauth://totp/CloudVault:evaluator?secret=JBSWY3DPEHPK3PXP&issuer=CloudVault",
            "recovery_codes": ["DEMO-RC01-9921", "DEMO-RC02-1142", "DEMO-RC03-7743", "DEMO-RC04-5512"]
        }

    def enable_mfa(self, token: str, secret: str, code: str) -> Dict[str, Any]:
        return {"status": "enabled", "message": "Demo MFA verified and activated."}

    def disable_mfa(self, token: str, password: str, code: str) -> Dict[str, Any]:
        return {"status": "disabled", "message": "Demo MFA deactivated."}

    def get_recovery_codes(self, token: str) -> Dict[str, Any]:
        return {
            "recovery_codes": ["DEMO-RC01-9921", "DEMO-RC02-1142", "DEMO-RC03-7743", "DEMO-RC04-5512"],
            "remaining": 4
        }

    # -------------------------------------------------------------
    # Backup Plans & Direct Upload
    # -------------------------------------------------------------
    def list_backup_plans(self, token: str) -> List[Dict[str, Any]]:
        return get_demo_state().plans

    def create_backup_plan(
        self,
        token: str,
        plan_name: str,
        source_directories: List[str],
        exclusion_patterns: Optional[List[str]] = None,
        schedule_type: str = "manual",
        schedule_expression: Optional[str] = None,
        retention_days: int = 30,
        compression_algo: str = "gzip"
    ) -> Dict[str, Any]:
        state = get_demo_state()
        new_plan = {
            "id": f"plan-demo-{len(state.plans) + 1:03d}",
            "plan_name": plan_name,
            "source_directories": source_directories,
            "exclusion_patterns": exclusion_patterns or [],
            "schedule_type": schedule_type,
            "schedule_expression": schedule_expression or "0 0 * * *",
            "retention_days": retention_days,
            "compression_algo": compression_algo
        }
        state.plans.append(new_plan)
        return new_plan

    def trigger_backup(self, token: str, plan_id: str) -> Dict[str, Any]:
        state = get_demo_state()
        new_job = {
            "id": f"job-demo-{len(state.jobs) + 101}",
            "plan_name": "Standard Production Vault (Demo)",
            "status": "COMPLETED",
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files_processed": len(state.files),
            "bytes_transferred": sum(f.get("file_size", 0) for f in state.files),
            "deduplication_ratio": 42.6
        }
        state.jobs.insert(0, new_job)
        return {"status": "SUCCESS", "job_id": new_job["id"], "message": "Demo backup job executed successfully."}

    def upload_file_direct(
        self,
        token: str,
        plan_id: str,
        filename: str,
        file_bytes: bytes,
        relative_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Interactive demonstration of direct file ingestion:
          - Enforces strict 5 MB demo upload limit.
          - Rejects dangerous executables and scripts.
          - Sanitizes filenames.
          - Calculates true SHA-256 cryptographic digest.
          - Demonstrates Content-Addressed Storage (CAS) deduplication live.
          - Generates isolated session snapshot.
        """
        from streamlit_app.api_client import APIError

        # 1. Size constraint
        if len(file_bytes) > MAX_DEMO_UPLOAD_BYTES:
            raise APIError(
                413,
                f"File size ({len(file_bytes):,} bytes) exceeds demo maximum limit of {MAX_DEMO_UPLOAD_BYTES // (1024*1024)} MB."
            )

        # 2. Executable extension check
        clean_name = sanitize_filename(filename)
        _, ext = os.path.splitext(clean_name)
        if ext.lower() in PROHIBITED_EXTENSIONS:
            raise APIError(
                400,
                f"Prohibited file type '{ext}' for demo security. Executable and script files cannot be ingested."
            )

        # 3. Calculate SHA-256 hash
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        entropy = calculate_shannon_entropy(file_bytes)
        state = get_demo_state()

        # 4. Check for Content-Addressed Deduplication
        is_dedup = sha256 in state.content_by_hash
        target_path = relative_path.strip() if relative_path else f"uploads/{clean_name}"
        # Ensure clean path
        target_path = target_path.replace("..", "").lstrip("/\\")

        # Record file
        file_entry = {
            "id": f"file-demo-{len(state.files) + 1:03d}",
            "relative_path": target_path,
            "file_size": len(file_bytes),
            "sha256_hash": sha256,
            "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "entropy": entropy,
            "is_deleted": False,
            "content": file_bytes
        }
        state.files.append(file_entry)
        state.content_by_hash[sha256] = file_bytes

        # 5. Create new Demo Snapshot
        new_snap_id = f"snap-demo-upload-{len(state.snapshots) + 1:03d}"
        stored_bytes_addition = 0 if is_dedup else int(len(file_bytes) * 0.65)  # simulated compression
        new_snapshot = {
            "id": new_snap_id,
            "name": f"Ad-hoc Upload ({clean_name})",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_files": len(state.files),
            "total_uncompressed_bytes": sum(f["file_size"] for f in state.files),
            "total_stored_bytes": state.snapshots[0]["total_stored_bytes"] + stored_bytes_addition,
            "worm_locked_until": "2026-12-04T00:00:00Z",
            "is_quarantined": False,
            "retention_policy": "standard_30d"
        }
        state.snapshots.insert(0, new_snapshot)

        return {
            "message": "File successfully uploaded, encrypted, and indexed into demonstration vault.",
            "filename": clean_name,
            "sha256": sha256,
            "deduplicated": is_dedup,
            "size_bytes": len(file_bytes),
            "snapshot_id": new_snap_id,
            "encryption_algo": "AES-256-GCM (Simulated Envelope)",
            "entropy": entropy,
            "demo_mode": True
        }

    def get_backup_jobs(self, token: str, limit: int = 50) -> List[Dict[str, Any]]:
        return get_demo_state().jobs[:limit]

    def get_storage_stats(self, token: str) -> Dict[str, Any]:
        state = get_demo_state()
        total_uncompressed = sum(f.get("file_size", 0) for f in state.files) + 1488977920
        total_stored = state.snapshots[0].get("total_stored_bytes", 864026624)
        dedup_bytes = max(0, total_uncompressed - total_stored)
        dedup_ratio = round((dedup_bytes / total_uncompressed * 100), 1) if total_uncompressed > 0 else 42.0

        return {
            "total_files": len(state.files) + 10,
            "total_snapshots": len(state.snapshots),
            "total_uncompressed_bytes": total_uncompressed,
            "total_stored_bytes": total_stored,
            "deduplicated_bytes": dedup_bytes,
            "deduplication_ratio": dedup_ratio,
            "quota_limit_bytes": 5 * 1024 * 1024 * 1024,  # 5 GB
            "quota_used_pct": round((total_stored / (5 * 1024 * 1024 * 1024)) * 100, 1),
            "demo_mode": True
        }

    # -------------------------------------------------------------
    # Snapshots & Recovery
    # -------------------------------------------------------------
    def list_snapshots(self, token: str, plan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return get_demo_state().snapshots

    def get_snapshot_tree(self, token: str, snapshot_id: str) -> List[Dict[str, Any]]:
        return get_demo_state().files

    def restore_file(
        self,
        token: str,
        snapshot_file_id: str,
        destination_directory: str,
        conflict_strategy: str = "keep_both"
    ) -> Dict[str, Any]:
        state = get_demo_state()
        target = next((f for f in state.files if f["id"] == snapshot_file_id), state.files[0])
        content = state.content_by_hash.get(target["sha256_hash"], target.get("content", b"Sample content"))
        recomputed_sha = hashlib.sha256(content).hexdigest()

        return {
            "status": "RESTORED",
            "destination": f"{destination_directory}/{os.path.basename(target['relative_path'])}",
            "original_sha256": target["sha256_hash"],
            "restored_sha256": recomputed_sha,
            "integrity_verified": (target["sha256_hash"] == recomputed_sha),
            "bytes_restored": len(content),
            "conflict_strategy": conflict_strategy,
            "file_bytes": content,
            "demo_mode": True
        }

    def restore_snapshot(
        self,
        token: str,
        snapshot_id: str,
        destination_directory: str,
        conflict_strategy: str = "keep_both"
    ) -> Dict[str, Any]:
        state = get_demo_state()
        snap = next((s for s in state.snapshots if s["id"] == snapshot_id), state.snapshots[0])
        return {
            "status": "COMPLETED",
            "snapshot_id": snap["id"],
            "destination": destination_directory,
            "files_restored": snap.get("total_files", 14),
            "bytes_restored": snap.get("total_stored_bytes", 864026624),
            "integrity_verified": True,
            "conflict_strategy": conflict_strategy,
            "demo_mode": True
        }

    def get_deleted_files(self, token: str, plan_id: str) -> List[Dict[str, Any]]:
        return [
            {
                "id": "del-demo-001",
                "relative_path": "legacy_docs/2025_annual_plan.docx",
                "file_size": 245760,
                "deleted_at": "2026-11-19T10:00:00Z",
                "last_snapshot_id": "snap-demo-20261118-001"
            }
        ]

    # -------------------------------------------------------------
    # Disaster Recovery Command Center
    # -------------------------------------------------------------
    def get_dr_metrics(self, token: str) -> Dict[str, Any]:
        return {
            "readiness_status": "OPTIMAL",
            "readiness_score": 98,
            "rto_seconds": 2.4,
            "rto_minutes": 0.04,
            "rpo_hours": 0.2,
            "rpo_minutes": 12,
            "last_drill_timestamp": "2026-11-20T08:30:00Z",
            "synthetic_drills_passed": 14,
            "synthetic_drills_failed": 0,
            "active_failover_ready": True
        }

    def get_dr_command_center(self, token: str) -> Dict[str, Any]:
        return {
            "dr_readiness_score": 98,
            "rto_target_seconds": 300,
            "rto_measured_seconds": 2.4,
            "rpo_target_seconds": 3600,
            "rpo_measured_seconds": 720,
            "status": "ALL_SYSTEMS_OPERATIONAL"
        }

    def run_dr_drill(self, token: str, snapshot_id: Optional[str] = None) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "drill_id": f"drill-demo-{int(time.time())}",
            "execution_duration_sec": 0.18,
            "integrity_verified_pct": 100.0,
            "rto_measured_sec": 2.1,
            "message": "Synthetic Disaster Recovery Drill completed with 100% bit-level integrity."
        }

    # -------------------------------------------------------------
    # Security, Ransomware & Cryptography
    # -------------------------------------------------------------
    def list_security_alerts(self, token: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        state = get_demo_state()
        if status and status.upper() != "ALL":
            return [a for a in state.alerts if a.get("status") == status.upper()]
        return state.alerts

    def resolve_alert(
        self,
        token: str,
        alert_id: str,
        resolution_notes: str = "Verified safe by user",
        unquarantine_snapshots: bool = True
    ) -> Dict[str, Any]:
        state = get_demo_state()
        for a in state.alerts:
            if a["id"] == alert_id:
                a["status"] = "RESOLVED"
                a["resolution_notes"] = resolution_notes
        return {"status": "RESOLVED", "alert_id": alert_id, "message": "Demo alert marked resolved."}

    def simulate_attack_test(self, token: str, scenario_type: str = "mass_encryption") -> Dict[str, Any]:
        state = get_demo_state()
        new_alert = {
            "id": f"alert-demo-{len(state.alerts) + 82}",
            "alert_type": "Synthetic Ransomware Simulation Test",
            "risk_score": 94,
            "status": "ACTIVE",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "reasons": [
                "Shannon entropy spike: 7.91 on simulated payload test_data.bin.locked",
                "Simulated rapid encryption burst: 25 files/sec",
                "Heuristic rule matched: Ransomware signature pattern"
            ],
            "affected_snapshot_ids": [state.snapshots[0]["id"]],
            "recommended_action": "Snapshot isolated into WORM lock quarantine."
        }
        state.alerts.insert(0, new_alert)
        return {
            "status": "SIMULATED",
            "scenario": scenario_type,
            "risk_score": 94,
            "alert_generated": new_alert["id"],
            "message": "Simulated ransomware anomaly injected into demo telemetry."
        }

    def list_audit_logs(self, token: str, limit: int = 50) -> Dict[str, Any]:
        return {"logs": get_demo_state().audit_chain[:limit], "total": len(get_demo_state().audit_chain)}

    def verify_audit_trail(self, token: str) -> Dict[str, Any]:
        return {
            "status": "VALID",
            "verified_blocks": len(get_demo_state().audit_chain) + 26,
            "tampering_detected": False,
            "message": "HMAC-SHA256 cryptographic audit chain validated with 100% integrity."
        }

    def get_crypto_status(self, token: str) -> Dict[str, Any]:
        return {
            "algorithm": "AES-256-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "kek_status": "ACTIVE",
            "kek_id": "kek-user-demo-master-2026",
            "deterministic_dek_enabled": True,
            "envelope_encryption_active": True
        }

    def rotate_crypto_key(self, token: str) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "new_kek_id": f"kek-user-demo-{int(time.time())}",
            "message": "Key Encryption Key (KEK) rotated. DEK envelopes re-wrapped."
        }

    # -------------------------------------------------------------
    # AI Assistant (Copilot)
    # -------------------------------------------------------------
    def query_ai_assistant(self, token: str, prompt: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Deterministic offline semantic AI copilot for the demonstration.
        Responds accurately to questions about backup health, DR metrics,
        deduplication savings, and ransomware protection without paid APIs.
        """
        q = prompt.strip().lower()
        state = get_demo_state()

        if any(w in q for w in ("rpo", "rto", "readiness", "drill", "disaster")):
            reply = (
                "📊 **Disaster Recovery Status:** Optimal (Readiness Index: 98%)\n\n"
                "- **Measured RTO:** 2.4 seconds (against a 5-minute SLA target)\n"
                "- **Calculated RPO:** 12 minutes (against a 1-hour SLA target)\n"
                "- **Synthetic Drills:** 14/14 automated drills passed successfully with bit-level validation.\n"
                "- **Failover Engine:** Multi-cloud routing active across GCS, S3, and Azure Blob."
            )
            return {"response": reply, "action_card": None}

        if any(w in q for w in ("dedup", "saving", "storage", "quota", "usage")):
            stats = self.get_storage_stats(token)
            reply = (
                f"💾 **Storage & Deduplication Analysis:**\n\n"
                f"- **Protected Data Volume:** {stats['total_uncompressed_bytes'] / (1024*1024*1024):.2f} GB\n"
                f"- **Physical Stored Volume:** {stats['total_stored_bytes'] / (1024*1024*1024):.2f} GB\n"
                f"- **Deduplication Savings:** {stats['deduplication_ratio']}% reduction ({stats['deduplicated_bytes'] / (1024*1024):.1f} MB saved via Content-Addressed Storage)\n"
                f"- **Current Demo Quota:** {stats['quota_used_pct']}% of 5.0 GB used."
            )
            return {"response": reply, "action_card": None}

        if any(w in q for w in ("threat", "ransomware", "alert", "security", "entropy")):
            active = [a for a in state.alerts if a.get("status") == "ACTIVE"]
            if active:
                reply = (
                    f"🛡️ **Security Alert Active:** {len(active)} potential anomaly detected.\n\n"
                    f"- **Alert ID:** {active[0]['id']} (Risk Score: {active[0]['risk_score']}/100)\n"
                    f"- **Primary Signal:** Shannon entropy cutoff exceeded (>7.50 bits/byte).\n"
                    f"- **Isolation:** Affected snapshot quarantined under immutable WORM retention."
                )
                action_card = {
                    "action_type": "RESOLVE_SECURITY_ALERT",
                    "confirmation_token": "hmac_conf_resolve_" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:16],
                    "description": "Approve administrator override to resolve security alert and unquarantine snapshot."
                }
                return {"response": reply, "action_card": action_card}
            else:
                reply = (
                    "🛡️ **Security Center Clean:** All snapshots healthy, zero active ransomware threats.\n"
                    "Shannon entropy heuristics and multi-signal burst detection are actively monitoring ingestion."
                )
                return {"response": reply, "action_card": None}

        if any(w in q for w in ("backup", "trigger", "run backup", "start")):
            reply = "⚡ Would you like me to trigger an immediate snapshot of your primary backup plan?"
            action_card = {
                "action_type": "TRIGGER_BACKUP_PLAN",
                "confirmation_token": "hmac_conf_backup_" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:16],
                "description": "Execute ad-hoc snapshot creation for 'Standard Production Vault (Demo)'."
            }
            return {"response": reply, "action_card": action_card}

        # Default intelligent response
        reply = (
            f"🤖 **CloudVault Copilot (Offline Semantic Mode):**\n\n"
            f"I have analyzed your demonstration vault ({len(state.files)} files, {len(state.snapshots)} snapshots).\n"
            f"- **System Health Score:** 96/100 (Optimal)\n"
            f"- **Encryption:** AES-256-GCM Envelope Encryption Active\n"
            f"- **DR Readiness:** 98% with 2.4s RTO benchmark\n\n"
            f"You can ask me about **disaster recovery**, **deduplication savings**, **ransomware defense**, or **triggering backup actions**."
        )
        return {"response": reply, "action_card": None}

    def confirm_ai_action(self, token: str, confirmation_token: str) -> Dict[str, Any]:
        return {
            "status": "EXECUTED",
            "confirmation_token": confirmation_token,
            "message": "Cryptographic HMAC verified. Privileged demonstration action executed successfully."
        }

    # -------------------------------------------------------------
    # Predictive Analytics
    # -------------------------------------------------------------
    def get_analytics_overview(self, token: str) -> Dict[str, Any]:
        return {
            "health_score": 96,
            "dr_readiness_score": 98,
            "dedup_efficiency_pct": 42.6,
            "growth_rate_daily_mb": 18.4,
            "estimated_days_to_quota": 232
        }

    def get_storage_forecast(self, token: str, days: int = 30) -> Dict[str, Any]:
        base_mb = 824.0
        daily_growth = 18.4
        points = []
        for d in range(0, days + 1, max(1, days // 10)):
            points.append({
                "date": f"Day +{d}",
                "projected_mb": round(base_mb + (d * daily_growth), 1)
            })

        return {
            "daily_growth_rate_mb": daily_growth,
            "days_until_quota_exceeded": 232,
            "r_squared": 0.96,
            "forecast_points": points,
            "demo_mode": True
        }

    def get_health_score(self, token: str) -> Dict[str, Any]:
        return {
            "overall_score": 96,
            "status": "HEALTHY",
            "metrics": {
                "backup_cadence_score": 98,
                "integrity_score": 100,
                "dedup_efficiency_score": 92,
                "encryption_score": 100
            },
            "recommendations": [
                "Maintain current daily synthetic backup cadence.",
                "WORM retention is active across all baseline snapshots."
            ]
        }

    def get_large_files(self, token: str, limit: int = 10) -> List[Dict[str, Any]]:
        state = get_demo_state()
        sorted_files = sorted(state.files, key=lambda x: x.get("file_size", 0), reverse=True)
        return [
            {
                "path": f.get("relative_path"),
                "size_bytes": f.get("file_size"),
                "sha256": f.get("sha256_hash", "")[:16] + "...",
                "modified": f.get("modified_at")
            }
            for f in sorted_files[:limit]
        ]

    def get_weekly_report(self, token: str) -> Dict[str, Any]:
        return {
            "report_generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "weekly_data_protected_mb": 1420.5,
            "weekly_storage_saved_mb": 596.2,
            "incident_count": 0,
            "drills_conducted": 7,
            "compliance_status": "COMPLIANT"
        }

    # -------------------------------------------------------------
    # Multi-Cloud Storage Status
    # -------------------------------------------------------------
    def get_storage_inventory(self, token: str) -> Dict[str, Any]:
        return {
            "primary_provider": "gcs",
            "secondary_provider": "s3",
            "failover_enabled": True,
            "active_bucket": "cloudvault-demo-gcs-bucket",
            "providers_status": {
                "gcs": "SIMULATED_ACTIVE",
                "s3": "SIMULATED_FAILOVER_READY",
                "azure": "SIMULATED_ARCHIVE_READY",
                "mock": "ACTIVE_AIR_GAPPED_LOCAL"
            },
            "demo_mode": True
        }

    def get_providers_matrix(self, token: str) -> Dict[str, Any]:
        return {
            "primary": "Google Cloud Storage (Architectural Demo)",
            "failover": "Amazon Web Services S3 (Architectural Demo)",
            "archive": "Microsoft Azure Blob (Architectural Demo)",
            "local_fallback": "Local Air-Gapped Engine (Active)",
            "compliance_support": {
                "gcs": {"worm": True, "cmek": True, "regions": "Multi-Region US"},
                "s3": {"worm": True, "object_lock": True, "regions": "us-east-1"},
                "azure": {"worm": True, "immutable_blob": True, "regions": "East US"}
            }
        }
