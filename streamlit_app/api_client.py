import os
import time
import requests
from typing import Dict, Any, Optional, List

class APIError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"[{status_code}] {detail}")


class AuthenticationExpiredError(APIError):
    """Raised specifically when a JWT token expires or is revoked (HTTP 401)."""
    def __init__(self, detail: str = "Session expired. Please log in again."):
        super().__init__(401, detail)


class ConfigurationError(Exception):
    """Raised when backend connection or environment configuration is invalid."""
    pass


def resolve_backend_url(base_url: Optional[str] = None, environment: Optional[str] = None) -> str:
    """
    Resolve backend API URL with strict configuration precedence:
      1. Explicit constructor argument
      2. Streamlit Community Cloud secrets: st.secrets["BACKEND_API_URL"]
      3. Environment variable: os.getenv("BACKEND_API_URL")
      4. Local fallback: http://localhost:8000 (only in development)
    Validates production constraints (HTTPS enforcement, rejection of localhost).
    """
    env = environment or os.getenv("ENVIRONMENT") or os.getenv("CLOUDVAULT_ENV", "development")
    
    # Check Streamlit secrets if available
    secret_url = None
    try:
        import streamlit as st
        if hasattr(st, "secrets") and st.secrets is not None:
            if "BACKEND_API_URL" in st.secrets:
                secret_url = st.secrets["BACKEND_API_URL"]
            elif "general" in st.secrets and "BACKEND_API_URL" in st.secrets["general"]:
                secret_url = st.secrets["general"]["BACKEND_API_URL"]
            if not environment and "ENVIRONMENT" in st.secrets:
                env = st.secrets["ENVIRONMENT"]
    except Exception:
        secret_url = None

    url = base_url or secret_url or os.getenv("BACKEND_API_URL")
    is_prod = str(env).lower() in ("production", "prod")

    if not url:
        if is_prod:
            raise ConfigurationError(
                "Production mode detected, but BACKEND_API_URL is missing. "
                "Configure BACKEND_API_URL in Streamlit secrets or environment variables."
            )
        url = "http://localhost:8000"

    url = str(url).strip().rstrip("/")

    if is_prod:
        if url.startswith("http://"):
            raise ConfigurationError(
                f"Production mode requires secure HTTPS protocol for BACKEND_API_URL. Insecure URL: {url}"
            )
        if "localhost" in url.lower() or "127.0.0.1" in url:
            raise ConfigurationError(
                f"Production mode cannot use localhost as BACKEND_API_URL. Configured URL: {url}"
            )

    return url


class CloudVaultClient:
    """
    Robust HTTP client for the CloudVault FastAPI backend.
    Accepts Bearer JWT authentication and connects seamlessly across local development,
    private LAN, and cloud deployments (Streamlit Cloud -> Render / Railway / Cloud Run).
    """

    def __init__(self, base_url: Optional[str] = None, environment: Optional[str] = None):
        self.base_url = resolve_backend_url(base_url, environment)
        self._health_cache = {"result": None, "timestamp": 0.0}

    def _headers(self, token: Optional[str] = None) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _handle_response(self, response: requests.Response) -> Any:
        try:
            data = response.json()
        except Exception:
            data = {"detail": response.text or "Unknown server response"}

        if not response.ok:
            detail = data.get("detail", f"Request failed with status {response.status_code}")
            if isinstance(detail, list):  # Pydantic validation errors
                detail = "; ".join([f"{e.get('loc', [''])[ -1]}: {e.get('msg', '')}" for e in detail])
            if response.status_code == 401:
                raise AuthenticationExpiredError(str(detail))
            raise APIError(response.status_code, str(detail))
        return data

    # -------------------------------------------------------------
    # System & Health
    # -------------------------------------------------------------
    def health_check(self, timeout: int = 45, force: bool = False) -> Dict[str, Any]:
        """
        Check backend health with cold-start awareness and short-lived caching.
        Timeout defaults to 45 seconds to accommodate serverless wake-up latencies.
        """
        now = time.time()
        # Return cached health if under 15 seconds old and healthy
        if not force and self._health_cache["result"] is not None:
            if (now - self._health_cache["timestamp"]) < 15.0:
                if self._health_cache["result"].get("status") == "healthy":
                    return self._health_cache["result"]

        url = f"{self.base_url}/api/v1/health"
        try:
            # Tuple timeout: 10s connect, (timeout-10)s read
            connect_timeout = min(10, timeout)
            read_timeout = max(5, timeout - connect_timeout)
            res = requests.get(url, headers=self._headers(), timeout=(connect_timeout, read_timeout))
            data = self._handle_response(res)
            self._health_cache = {"result": data, "timestamp": now}
            return data
        except requests.exceptions.ConnectTimeout:
            res_data = {
                "status": "cold_start",
                "message": "Backend server is spinning up from cold start. Please retry in 15-30 seconds.",
                "storage_provider": "unknown",
                "version": "2.0.0"
            }
            self._health_cache = {"result": res_data, "timestamp": now}
            return res_data
        except requests.exceptions.ReadTimeout:
            res_data = {
                "status": "slow_response",
                "message": "Backend response timed out during computation.",
                "storage_provider": "unknown",
                "version": "2.0.0"
            }
            self._health_cache = {"result": res_data, "timestamp": now}
            return res_data
        except requests.exceptions.ConnectionError:
            res_data = {
                "status": "unreachable",
                "message": f"Cannot connect to backend at {self.base_url}. Verify server status and network.",
                "storage_provider": "unknown",
                "version": "2.0.0"
            }
            self._health_cache = {"result": res_data, "timestamp": now}
            return res_data
        except Exception as e:
            res_data = {
                "status": "error",
                "message": f"Health check failed: {str(e)}",
                "storage_provider": "unknown",
                "version": "2.0.0"
            }
            self._health_cache = {"result": res_data, "timestamp": now}
            return res_data

    # -------------------------------------------------------------
    # Authentication & User Profile
    # -------------------------------------------------------------
    def register(self, email: str, password: str, full_name: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/auth/register"
        payload = {"email": email, "password": password, "full_name": full_name}
        res = requests.post(url, json=payload, headers=self._headers(), timeout=15)
        return self._handle_response(res)

    def login(self, email: str, password: str, mfa_code: Optional[str] = None) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/auth/login"
        payload = {"email": email, "password": password, "mfa_code": mfa_code}
        res = requests.post(url, json=payload, headers=self._headers(), timeout=15)
        return self._handle_response(res)

    def get_me(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/auth/me"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def setup_mfa(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/auth/mfa/setup"
        res = requests.post(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def enable_mfa(self, token: str, secret: str, code: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/auth/mfa/enable"
        payload = {"secret": secret, "code": code}
        res = requests.post(url, json=payload, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def disable_mfa(self, token: str, password: str, code: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/auth/mfa/disable"
        payload = {"password": password, "code": code}
        res = requests.post(url, json=payload, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def get_recovery_codes(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/auth/mfa/recovery-codes"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    # -------------------------------------------------------------
    # Backup Plans & Operations
    # -------------------------------------------------------------
    def list_backup_plans(self, token: str) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v1/backups/plans"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

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
        url = f"{self.base_url}/api/v1/backups/plans"
        payload = {
            "plan_name": plan_name,
            "source_directories": source_directories,
            "exclusion_patterns": exclusion_patterns or [],
            "schedule_type": schedule_type,
            "schedule_expression": schedule_expression,
            "retention_days": retention_days,
            "compression_algo": compression_algo
        }
        res = requests.post(url, json=payload, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def trigger_backup(self, token: str, plan_id: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/backups/plans/{plan_id}/trigger"
        res = requests.post(url, headers=self._headers(token), timeout=60)
        return self._handle_response(res)

    def upload_file_direct(
        self,
        token: str,
        plan_id: str,
        filename: str,
        file_bytes: bytes,
        relative_path: Optional[str] = None
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/backups/upload-file"
        data = {"plan_id": plan_id}
        if relative_path:
            data["relative_path"] = relative_path
        files = {"file": (filename, file_bytes, "application/octet-stream")}
        res = requests.post(url, data=data, files=files, headers=self._headers(token), timeout=120)
        return self._handle_response(res)

    def get_backup_jobs(self, token: str, limit: int = 50) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v1/backups/jobs?limit={limit}"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def get_storage_stats(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/backups/stats"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    # -------------------------------------------------------------
    # Recovery & Snapshots
    # -------------------------------------------------------------
    def list_snapshots(self, token: str, plan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v1/recovery/snapshots"
        if plan_id:
            url += f"?plan_id={plan_id}"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def get_snapshot_tree(self, token: str, snapshot_id: str) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v1/recovery/snapshots/{snapshot_id}/tree"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def restore_file(
        self,
        token: str,
        snapshot_file_id: str,
        destination_directory: str,
        conflict_strategy: str = "keep_both"
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/recovery/restore-file"
        payload = {
            "snapshot_file_id": snapshot_file_id,
            "destination_directory": destination_directory,
            "conflict_strategy": conflict_strategy
        }
        res = requests.post(url, json=payload, headers=self._headers(token), timeout=30)
        return self._handle_response(res)

    def restore_snapshot(
        self,
        token: str,
        snapshot_id: str,
        destination_directory: str,
        conflict_strategy: str = "keep_both"
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/recovery/restore-snapshot"
        payload = {
            "snapshot_id": snapshot_id,
            "destination_directory": destination_directory,
            "conflict_strategy": conflict_strategy
        }
        res = requests.post(url, json=payload, headers=self._headers(token), timeout=60)
        return self._handle_response(res)

    def get_deleted_files(self, token: str, plan_id: str) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v1/recovery/deleted-files?plan_id={plan_id}"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    # -------------------------------------------------------------
    # Disaster Recovery (DR) Command Center
    # -------------------------------------------------------------
    def get_dr_metrics(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/dr/metrics"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def get_dr_command_center(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/dr/command-center"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def run_dr_drill(self, token: str, snapshot_id: Optional[str] = None) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/dr/simulate-drill"
        payload = {"snapshot_id": snapshot_id}
        res = requests.post(url, json=payload, headers=self._headers(token), timeout=30)
        return self._handle_response(res)

    # -------------------------------------------------------------
    # Security, Ransomware & Cryptography
    # -------------------------------------------------------------
    def list_security_alerts(self, token: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v1/security/alerts"
        if status:
            url += f"?status={status}"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def resolve_alert(
        self,
        token: str,
        alert_id: str,
        resolution_notes: str = "Verified safe by user",
        unquarantine_snapshots: bool = True
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/security/alerts/{alert_id}/resolve"
        payload = {
            "resolution_notes": resolution_notes,
            "unquarantine_snapshots": unquarantine_snapshots
        }
        res = requests.post(url, json=payload, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def simulate_attack_test(self, token: str, scenario_type: str = "mass_encryption") -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/security/simulate-test"
        payload = {"scenario_type": scenario_type}
        res = requests.post(url, json=payload, headers=self._headers(token), timeout=25)
        return self._handle_response(res)

    def list_audit_logs(self, token: str, limit: int = 50) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/security/audit-logs?limit={limit}"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def verify_audit_trail(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/security/audit-logs/verify"
        res = requests.get(url, headers=self._headers(token), timeout=20)
        return self._handle_response(res)

    def get_crypto_status(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/security/crypto/status"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def rotate_crypto_key(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/security/crypto/rotate-key"
        res = requests.post(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    # -------------------------------------------------------------
    # AI Assistant (Copilot)
    # -------------------------------------------------------------
    def query_ai_assistant(self, token: str, prompt: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/ai/query"
        payload = {"prompt": prompt, "session_id": session_id}
        res = requests.post(url, json=payload, headers=self._headers(token), timeout=30)
        return self._handle_response(res)

    def confirm_ai_action(self, token: str, confirmation_token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/ai/confirm-action"
        payload = {"confirmation_token": confirmation_token}
        res = requests.post(url, json=payload, headers=self._headers(token), timeout=30)
        return self._handle_response(res)

    # -------------------------------------------------------------
    # Analytics & Forecast
    # -------------------------------------------------------------
    def get_analytics_overview(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/analytics/overview"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def get_storage_forecast(self, token: str, days: int = 30) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/analytics/storage-forecast?days={days}"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def get_health_score(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/analytics/health-score"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def get_large_files(self, token: str, limit: int = 10) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v1/analytics/large-files?limit={limit}"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def get_weekly_report(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/analytics/weekly-report"
        res = requests.get(url, headers=self._headers(token), timeout=20)
        return self._handle_response(res)

    # -------------------------------------------------------------
    # Multi-Cloud Storage Status
    # -------------------------------------------------------------
    def get_storage_inventory(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/storage/inventory"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)

    def get_providers_matrix(self, token: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/storage/providers"
        res = requests.get(url, headers=self._headers(token), timeout=15)
        return self._handle_response(res)
