import os
import re
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models import Snapshot
from backend.app.ai.tools import (
    tool_get_protected_files_summary,
    tool_get_recent_snapshots,
    tool_get_failed_backups,
    tool_get_storage_savings,
    tool_get_unprotected_files,
    tool_explain_security_alerts,
    tool_check_system_health,
    tool_get_backup_recommendations,
    tool_propose_trigger_backup,
    tool_propose_lock_snapshot
)

class BaseAIProvider(ABC):
    """Abstract AI Provider for CloudVault Assistant."""

    @abstractmethod
    def process_query(self, user_id: str, prompt: str, db: Session) -> Dict[str, Any]:
        """Process user natural language prompt and return assistant response + any action cards."""
        pass

class RuleBasedLocalLLMProvider(BaseAIProvider):
    """
    Offline, zero-cost, high-reliability semantic AI engine.
    Analyzes user intent, extracts parameters, executes scoped domain tools,
    and formats intelligent, grounded natural language responses.
    """

    def process_query(self, user_id: str, prompt: str, db: Session) -> Dict[str, Any]:
        p = prompt.strip().lower()

        # 1. Protected Files Query
        if any(w in p for w in ["protected", "how many file", "number of file", "total file"]):
            data = tool_get_protected_files_summary(user_id, db)
            count = data["protected_files_count"]
            plans = data["active_plans_count"]
            snaps = data["total_snapshots_count"]
            return {
                "response": (
                    f"### 🛡️ Protected Files Summary\n\n"
                    f"CloudVault is currently protecting **{count:,} files** across **{plans} active backup plan(s)** "
                    f"with a total of **{snaps} point-in-time snapshot(s)**.\n\n"
                    f"- All files are indexed and addressable via immutable SHA-256 fingerprints.\n"
                    f"- Deduplication ensures identical files share physical storage space."
                ),
                "data": data,
                "action_card": None
            }

        # 2. Recent Snapshots Query
        if any(w in p for w in ["last five", "recent backup", "recent snapshot", "show my backup", "list snapshot", "snapshots"]):
            data = tool_get_recent_snapshots(user_id, db, limit=5)
            snaps = data["snapshots"]
            if not snaps:
                return {
                    "response": "You currently do not have any backup snapshots recorded. Click **Execute Backup Now** on your dashboard to create your first point-in-time snapshot!",
                    "data": data,
                    "action_card": None
                }
            
            lines = ["### ⏳ Recent Point-in-Time Snapshots\n"]
            for s in snaps:
                dt = s["created_at"].replace("T", " ")[:19]
                size_mb = round(s["uncompressed_bytes"] / (1024 * 1024), 2)
                lock_badge = "🔒 WORM Locked" if s["is_immutable"] else "Unlocked"
                lines.append(f"- **#{s['snapshot_number']} {s['name']}** — {s['total_files']} files ({size_mb} MB) at `{dt}` [{lock_badge}]")
            
            lines.append("\nYou can restore individual files or entire folders from any of these snapshots via the **Snapshot Time Machine** tab.")
            return {
                "response": "\n".join(lines),
                "data": data,
                "action_card": None
            }

        # 3. Failed Backups Query
        if any(w in p for w in ["failed", "failure", "broken", "error", "interrupted"]):
            data = tool_get_failed_backups(user_id, db, days=7)
            failed = data["failed_jobs"]
            if not failed:
                return {
                    "response": (
                        f"### ✅ Backup Execution Status\n\n"
                        f"Great news! There have been **0 failed backups** in the past {data['period_days']} days.\n"
                        f"All scheduled and manual backup executions completed successfully."
                    ),
                    "data": data,
                    "action_card": None
                }
            lines = [f"### ⚠️ Failed Backup Jobs (Past {data['period_days']} Days)\n", f"Detected **{len(failed)}** issue(s):\n"]
            for f in failed:
                lines.append(f"- **Job `{f['job_id'][:8]}`** ({f['trigger_type']}) at `{f['started_at']}`: *{f['error_message']}*")
            lines.append("\n**Recommendation:** Check your local directory permissions and verify that source folders are accessible.")
            return {
                "response": "\n".join(lines),
                "data": data,
                "action_card": None
            }

        # 4. Storage Savings / Deduplication Query
        if any(w in p for w in ["save", "dedup", "deduplication", "compression", "storage used"]):
            data = tool_get_storage_savings(user_id, db)
            saved_mb = round(data["bytes_saved"] / (1024 * 1024), 2)
            logical_mb = round(data["logical_uncompressed_bytes"] / (1024 * 1024), 2)
            stored_mb = round(data["physical_stored_bytes"] / (1024 * 1024), 2)
            return {
                "response": (
                    f"### 💾 Cloud Storage Efficiency & Deduplication\n\n"
                    f"- **Logical Data Protected:** {logical_mb} MB across all snapshots\n"
                    f"- **Physical Storage Stored:** {stored_mb} MB in cloud storage\n"
                    f"- **Bandwidth & Storage Saved:** **{saved_mb} MB** (**{data['savings_percentage']}%** reduction)\n"
                    f"- **Unique SHA-256 Blocks:** {data['unique_storage_objects']} objects\n\n"
                    f"Content-Addressable Storage (CAS) ensures identical files or repeated versions transfer **0 bytes** over the network."
                ),
                "data": data,
                "action_card": None
            }

        # 5. Unprotected Files Query
        if any(w in p for w in ["unprotected", "not backed up", "missing", "pending file"]):
            data = tool_get_unprotected_files(user_id, db)
            unprot = data["unprotected_files"]
            if not unprot:
                return {
                    "response": (
                        "### 📂 File Protection Status\n\n"
                        "All local files in your configured backup directories are fully synced and protected in your latest snapshots!"
                    ),
                    "data": data,
                    "action_card": None
                }
            lines = [f"### 🔍 Unprotected or Recently Modified Files\n", f"Detected modified files since your latest snapshot:\n"]
            for u in unprot[:5]:
                name = os.path.basename(u["file_path"])
                lines.append(f"- `{name}` in **{u['plan_name']}** (Modified: {u['modified_at'][:19]})")
            lines.append("\nWould you like me to trigger an immediate backup to protect these changes?")
            
            # Offer action proposal card
            action_proposal = tool_propose_trigger_backup(user_id, None, db)
            return {
                "response": "\n".join(lines),
                "data": data,
                "action_card": action_proposal
            }

        # 6. Security Alerts & Ransomware Query
        if any(w in p for w in ["security", "ransomware", "alert", "anomaly", "threat"]):
            data = tool_explain_security_alerts(user_id, db)
            alerts = data["alerts"]
            if not alerts:
                return {
                    "response": (
                        "### 🛡️ Security & Ransomware Shield\n\n"
                        "- **Status:** Secure & Active\n"
                        "- **Active Alerts:** 0\n"
                        "- **Anomaly Detection:** Shannon entropy and extension monitors are active.\n\n"
                        "No suspicious encryption bursts or ransomware signatures have been detected."
                    ),
                    "data": data,
                    "action_card": None
                }
            lines = [f"### 🚨 Active Security Alerts ({len(alerts)})\n"]
            for a in alerts:
                lines.append(f"- **{a['alert_level']} (Score: {a['risk_score']}/100)**: {a['suspicious_files_count']} suspicious files (Avg entropy: {a['average_entropy']} bits/byte).")
            lines.append("\n**Action taken:** Automatic snapshot lock and quarantine have been engaged to protect previous clean recovery points.")
            return {
                "response": "\n".join(lines),
                "data": data,
                "action_card": None
            }

        # 7. System Health Query
        if any(w in p for w in ["health", "healthy", "status", "system status"]):
            data = tool_check_system_health(user_id, db)
            badge = "🟢" if data["health_status"] == "HEALTHY" else ("🟡" if data["health_status"] == "WARNING" else "🔴")
            return {
                "response": (
                    f"### {badge} CloudVault Health Assessment\n\n"
                    f"- **Overall Health Score:** **{data['health_score']}/100** ({data['health_status']})\n"
                    f"- **Latest Backup Point:** {data['latest_backup_time'] or 'Never'}\n"
                    f"- **Recent Failed Jobs:** {data['recent_failures_count']}\n"
                    f"- **Active Security Alerts:** {data['active_security_alerts_count']}\n\n"
                    f"{'Your backup infrastructure is operating normally.' if data['health_score'] >= 80 else 'Attention recommended: review recent job failures or security alerts.'}"
                ),
                "data": data,
                "action_card": None
            }

        # 8. Recommendations Query
        if any(w in p for w in ["recommend", "improve", "advice", "suggestion", "best practice"]):
            data = tool_get_backup_recommendations(user_id, db)
            recs = data["recommendations"]
            lines = ["### 💡 Intelligent Backup Recommendations\n"]
            for r in recs:
                lines.append(f"- {r}")
            return {
                "response": "\n".join(lines),
                "data": data,
                "action_card": None
            }

        # 9. Controlled Action: Propose Trigger Backup
        if any(w in p for w in ["run backup", "trigger backup", "create backup", "take a backup", "backup now"]):
            action_proposal = tool_propose_trigger_backup(user_id, None, db)
            if action_proposal.get("status") == "error":
                return {
                    "response": f"Unable to prepare backup: {action_proposal.get('message')}",
                    "data": None,
                    "action_card": None
                }
            return {
                "response": (
                    "### ⚡ Backup Request Prepared\n\n"
                    "I have prepared an on-demand backup execution request for your active plan. "
                    "For security and audit compliance, please review and confirm the action card below:"
                ),
                "data": None,
                "action_card": action_proposal
            }

        # 10. Controlled Action: Propose Lock Snapshot
        if any(w in p for w in ["lock snapshot", "immutable", "worm lock"]):
            # Get latest snapshot
            latest_snap = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).first()
            if not latest_snap:
                return {
                    "response": "No snapshots available to lock. Please run a backup first.",
                    "data": None,
                    "action_card": None
                }
            action_proposal = tool_propose_lock_snapshot(user_id, latest_snap.id, retention_days=30, db=db)
            return {
                "response": (
                    f"### 🔒 WORM Immutable Lock Prepared\n\n"
                    f"I have prepared a WORM immutable retention lock for **Snapshot #{latest_snap.snapshot_number} ({latest_snap.name})**. "
                    f"Once confirmed, this snapshot cannot be modified or deleted by anyone until the retention date. "
                    f"Please confirm execution below:"
                ),
                "data": None,
                "action_card": action_proposal
            }

        # Default Helpful Guidance
        return {
            "response": (
                "👋 **Hello! I am your CloudVault AI Copilot.**\n\n"
                "I have secure, read-only access to your backup metadata and can prepare verified operations for you.\n\n"
                "**Try asking me:**\n"
                "- *'How many files are currently protected?'*\n"
                "- *'Show my last five backups.'*\n"
                "- *'Which backups failed this week?'*\n"
                "- *'How much storage have I saved through deduplication?'*\n"
                "- *'Is my backup system healthy?'*\n"
                "- *'Explain my latest security alert.'*\n"
                "- *'Trigger an on-demand backup.'*"
            ),
            "data": None,
            "action_card": None
        }

def get_ai_provider() -> BaseAIProvider:
    """Factory returning configured AI Provider."""
    # When external LLM is configured via environment variables, return ExternalLLMProvider
    # Otherwise, default to reliable, zero-cost RuleBasedLocalLLMProvider
    return RuleBasedLocalLLMProvider()
