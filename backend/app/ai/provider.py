import os
import re
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from urllib import request as urllib_request
from urllib.error import URLError, HTTPError
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models import (
    User, Snapshot, BackupPlan, RansomwareAlert, StorageObject,
    MFARecoveryCode, DRDrill, AuditLog
)
from backend.app.ai.security import verify_audit_log_chain
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
    tool_propose_lock_snapshot,
    tool_propose_restore_file,
    tool_propose_verify_snapshot
)

logger = logging.getLogger("cloudvault.ai")

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

    FALLBACK_NOTICE = "\n\n*(⚡ CloudVault Deterministic Local Semantic Engine — Air-Gapped Fallback)*"

    def process_query(self, user_id: str, prompt: str, db: Session) -> Dict[str, Any]:
        p = prompt.strip().lower()

        # 1. Protected Files Query
        if any(w in p for w in ["protected file", "files are currently protected", "files protected", "how many file", "how many files", "number of file", "total file", "total files"]):
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
                    f"{self.FALLBACK_NOTICE}"
                ),
                "data": data,
                "action_card": None
            }

        # 2. Recent Snapshots / Latest Five Backups Query
        if any(w in p for w in ["last five", "recent backup", "recent snapshot", "recent snapshots", "show my backup", "list snapshot", "list snapshots", "latest backup", "latest snapshots", "show snapshots"]):
            data = tool_get_recent_snapshots(user_id, db, limit=5)
            snaps = data["snapshots"]
            if not snaps:
                return {
                    "response": (
                        "You currently do not have any backup snapshots recorded. Click **Execute Backup Now** on your dashboard to create your first point-in-time snapshot!"
                        f"{self.FALLBACK_NOTICE}"
                    ),
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
            lines.append(self.FALLBACK_NOTICE)
            return {
                "response": "\n".join(lines),
                "data": data,
                "action_card": None
            }

        # 3. Failed Backups Query & Explanation
        if any(w in p for w in ["failed", "failure", "broken", "error", "interrupted", "why did backup fail"]):
            data = tool_get_failed_backups(user_id, db, days=7)
            failed = data["failed_jobs"]
            if not failed:
                return {
                    "response": (
                        f"### ✅ Backup Execution Status\n\n"
                        f"Great news! There have been **0 failed backups** in the past {data['period_days']} days.\n"
                        f"All scheduled and manual backup executions completed successfully."
                        f"{self.FALLBACK_NOTICE}"
                    ),
                    "data": data,
                    "action_card": None
                }
            lines = [f"### ⚠️ Failed Backup Jobs (Past {data['period_days']} Days)\n", f"Detected **{len(failed)}** issue(s):\n"]
            for f in failed:
                lines.append(f"- **Job `{f['job_id'][:8]}`** ({f['trigger_type']}) at `{f['started_at']}`: *{f['error_message']}*")
            lines.append("\n**Recommendation:** Check your local directory permissions and verify that source folders are accessible.")
            lines.append(self.FALLBACK_NOTICE)
            return {
                "response": "\n".join(lines),
                "data": data,
                "action_card": None
            }

        # 4. Storage Savings, Deduplication & Storage Usage Query
        if any(w in p for w in ["save", "dedup", "deduplication", "compression", "storage used", "storage usage", "explain my storage", "storage report"]):
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
                    f"{self.FALLBACK_NOTICE}"
                ),
                "data": data,
                "action_card": None
            }

        # 5. Unprotected Files Query
        if any(w in p for w in ["unprotected", "not backed up", "missing", "pending file", "not been backed up recently"]):
            data = tool_get_unprotected_files(user_id, db)
            unprot = data["unprotected_files"]
            if not unprot:
                return {
                    "response": (
                        "### 📂 File Protection Status\n\n"
                        "All local files in your configured backup directories are fully synced and protected in your latest snapshots!"
                        f"{self.FALLBACK_NOTICE}"
                    ),
                    "data": data,
                    "action_card": None
                }
            lines = [f"### 🔍 Unprotected or Recently Modified Files\n", f"Detected modified files since your latest snapshot:\n"]
            for u in unprot[:5]:
                name = os.path.basename(u["file_path"])
                lines.append(f"- `{name}` in **{u['plan_name']}** (Modified: {u['modified_at'][:19]})")
            lines.append("\nWould you like me to trigger an immediate backup to protect these changes?")
            lines.append(self.FALLBACK_NOTICE)
            
            action_proposal = tool_propose_trigger_backup(user_id, None, db)
            return {
                "response": "\n".join(lines),
                "data": data,
                "action_card": action_proposal
            }

        # 6. Security Alerts, Ransomware & Anomaly Queries
        if any(w in p for w in [
            "security alert", "security alerts", "ransomware", "alert", "anomaly", "threat", "suspicious",
            "why was this backup flagged", "why was my backup flagged", "flagged",
            "which files are affected", "files affected", "risk level", "current risk",
            "which clean snapshot", "clean recovery", "clean snapshot", "what should i do next"
        ]):
            data = tool_explain_security_alerts(user_id, db)
            alerts = data["alerts"]
            clean_snap = data.get("clean_recovery_snapshot")

            # 6A. Specific query: "Which clean snapshot should I recover?"
            if any(w in p for w in ["clean snapshot", "which clean", "recover clean", "clean recovery"]):
                if not clean_snap:
                    return {
                        "response": (
                            "### ⏳ Clean Recovery Point Recommendation\n\n"
                            "No prior clean snapshots were found in your repository history. "
                            "Please run an on-demand verified backup of your known-clean source folders."
                            f"{self.FALLBACK_NOTICE}"
                        ),
                        "data": data,
                        "action_card": None
                    }
                lock_text = "🔒 WORM Shielded" if clean_snap["is_immutable"] else "Active"
                return {
                    "response": (
                        f"### 🛡️ Recommended Clean Recovery Point\n\n"
                        f"The safest point-in-time snapshot to recover is **Snapshot #{clean_snap['snapshot_number']} ({clean_snap['name']})**.\n\n"
                        f"- **Snapshot ID:** `{clean_snap['snapshot_id']}`\n"
                        f"- **Creation Timestamp:** `{clean_snap['created_at'][:19].replace('T', ' ')} UTC`\n"
                        f"- **Files Preserved:** {clean_snap['total_files']} files\n"
                        f"- **Integrity Status:** {lock_text} (Preserved prior to anomalous activity)\n\n"
                        f"You can restore files from this verified snapshot using the **Snapshot Time Machine** tab or by asking me to *'Restore a file'*."
                        f"{self.FALLBACK_NOTICE}"
                    ),
                    "data": {"recommended_snapshot": clean_snap},
                    "action_card": None
                }

            # 6B. Specific query: "What should I do next?"
            if any(w in p for w in ["what should i do next", "next step", "what to do"]):
                if not alerts:
                    return {
                        "response": (
                            "### 🛡️ Security Posture & Next Steps\n\n"
                            "Your CloudVault system is completely clean with **0 active security alerts**.\n\n"
                            "**Recommended Next Steps:**\n"
                            "1. Keep scheduled backups active to protect against sudden file modifications.\n"
                            "2. Ensure AES-256-GCM encryption is enabled for all plans.\n"
                            "3. Run periodic synthetic recovery drills to verify SHA-256 hash fidelity."
                            f"{self.FALLBACK_NOTICE}"
                        ),
                        "data": data,
                        "action_card": None
                    }
                top_alert = alerts[0]
                rec_lines = [
                    f"### 🛡️ Security Remediation Steps (Risk Score: {top_alert['risk_score']}/100)\n",
                    "**Immediate Actions Required:**\n",
                    f"1. **Isolate infected folders:** Suspicious extensions detected: `{', '.join(top_alert['matched_extensions']) if top_alert['matched_extensions'] else 'None'}`.",
                    f"2. **Preserve clean backups:** Previous clean snapshots have been automatically shielded with WORM locks.",
                    f"3. **Recover from clean point:** Recover known-clean files from **Snapshot #{clean_snap['snapshot_number'] if clean_snap else '1'}**.",
                    "4. **Review & Resolve:** Navigate to the **Security & Ransomware Shield** tab in the dashboard to inspect the full file list or resolve the alert."
                ]
                rec_lines.append(self.FALLBACK_NOTICE)
                return {
                    "response": "\n".join(rec_lines),
                    "data": data,
                    "action_card": None
                }

            # 6C. Specific query: "Which files are affected?" or "Why was this backup flagged?"
            if any(w in p for w in ["which files are affected", "files affected", "why was this backup flagged", "why was my backup flagged"]):
                if not alerts:
                    return {
                        "response": (
                            "### ✅ File Integrity Status\n\n"
                            "No files are currently affected or flagged by ransomware anomaly detection. All local files match expected patterns."
                            f"{self.FALLBACK_NOTICE}"
                        ),
                        "data": data,
                        "action_card": None
                    }
                top_alert = alerts[0]
                reasons_formatted = "\n".join([f"- {r}" for r in top_alert["reasons"]])
                return {
                    "response": (
                        f"### 🔍 Flagged Backup & Affected Files Analysis\n\n"
                        f"- **Alert Level:** **{top_alert['alert_level']}** (Risk Score: **{top_alert['risk_score']}/100**)\n"
                        f"- **Affected Files Count:** **{top_alert['suspicious_files_count']} file(s)**\n"
                        f"- **Matched Signatures:** `{', '.join(top_alert['matched_extensions']) if top_alert['matched_extensions'] else 'High Entropy Ciphertext Anomaly'}`\n"
                        f"- **Average Entropy:** {top_alert['average_entropy']} bits/byte\n\n"
                        f"**Detection Reasons:**\n{reasons_formatted}\n\n"
                        f"**Protection Status:** Automatic snapshot shielding engaged. Previous clean backups are immutable and safe."
                        f"{self.FALLBACK_NOTICE}"
                    ),
                    "data": data,
                    "action_card": None
                }

            # 6D. General Security Alerts & Threat Status Query
            if not alerts:
                return {
                    "response": (
                        "### 🛡️ Security & Ransomware Shield\n\n"
                        "- **Status:** Secure & Active\n"
                        "- **Active Alerts:** 0\n"
                        "- **Anomaly Detection:** Shannon entropy and extension monitors are active.\n\n"
                        "No suspicious encryption bursts or ransomware signatures have been detected."
                        f"{self.FALLBACK_NOTICE}"
                    ),
                    "data": data,
                    "action_card": None
                }

            lines = [f"### 🚨 Active Security Alerts ({len(alerts)})\n"]
            for a in alerts:
                lines.append(f"- **{a['alert_level']} (Score: {a['risk_score']}/100)**: {a['suspicious_files_count']} suspicious files (Avg entropy: {a['average_entropy']} bits/byte).")
                for r in a["reasons"][:2]:
                    lines.append(f"  * {r}")
            if clean_snap:
                lines.append(f"\n**Safe Recovery Point:** Snapshot #{clean_snap['snapshot_number']} ({clean_snap['name']}) is shielded and available for clean restore.")
            lines.append("\n**Action taken:** Automatic snapshot lock and quarantine have been engaged to protect previous clean recovery points.")
            lines.append(self.FALLBACK_NOTICE)
            return {
                "response": "\n".join(lines),
                "data": data,
                "action_card": None
            }

        # 7. System Health Query ("How healthy is my backup system?")
        if any(w in p for w in ["health", "healthy", "how healthy", "system status", "backup system healthy", "health score"]):
            data = tool_check_system_health(user_id, db)
            badge = "🟢" if data["health_status"] == "HEALTHY" or data["health_status"] == "EXCELLENT" else ("🟡" if data["health_status"] == "NEEDS_ATTENTION" or data["health_status"] == "WARNING" else "🔴")
            
            breakdown = data.get("breakdown", {})
            recs = data.get("recommendations", [])
            recs_text = "\n".join([f"- {r}" for r in recs[:3]]) if recs else "- All protection dimensions optimal."

            return {
                "response": (
                    f"### {badge} CloudVault Backup Health Assessment\n\n"
                    f"- **Overall Health Score:** **{data['health_score']}/100** ({data['health_status']})\n"
                    f"- **RPO Recency & Freshness:** {breakdown.get('rpo_score', 0)}/35 pts (Last snapshot: {data['latest_backup_time'] or 'Never'})\n"
                    f"- **Job Reliability & Success:** {breakdown.get('job_reliability_score', 0)}/25 pts\n"
                    f"- **Security & Ransomware Shield:** {breakdown.get('security_posture_score', 0)}/15 pts ({data['active_security_alerts_count']} alerts)\n"
                    f"- **Snapshot Integrity & DR:** {breakdown.get('drill_integrity_score', 0)}/10 pts\n"
                    f"- **Retention & WORM Protection:** {breakdown.get('retention_protection_score', 0)}/5 pts\n"
                    f"- **Deduplication & Coverage:** {breakdown.get('dedup_efficiency_score', 0)}/10 pts\n\n"
                    f"**Actionable Insights:**\n{recs_text}"
                    f"{self.FALLBACK_NOTICE}"
                ),
                "data": data,
                "action_card": None
            }

        # 8A. Weekly Executive Report Query ("Generate my weekly report")
        if any(w in p for w in ["weekly report", "generate weekly report", "executive report", "weekly summary", "report for this week"]):
            from backend.app.services.analytics_service import generate_weekly_report
            report_data = generate_weekly_report(user_id, db)
            return {
                "response": report_data["markdown_report"] + self.FALLBACK_NOTICE,
                "data": report_data,
                "action_card": None
            }

        # 8B. Predictive Storage Forecast Query ("What is likely to happen to my storage over the next month?")
        if any(w in p for w in ["likely to happen to my storage", "next month", "storage over the next month", "storage forecast", "future storage", "will my storage grow", "projected storage"]):
            from backend.app.services.analytics_service import get_storage_forecast
            forecast = get_storage_forecast(user_id, db, forecast_days=30)
            proj = forecast.get("projections", {})
            cur_mb = round(forecast["current_stored_bytes"] / (1024 * 1024), 2)
            d7_mb = round(proj.get("day_7_bytes", forecast["current_stored_bytes"]) / (1024 * 1024), 2)
            d14_mb = round(proj.get("day_14_bytes", forecast["current_stored_bytes"]) / (1024 * 1024), 2)
            d30_mb = round(proj.get("day_30_bytes", forecast["projected_bytes_30d"]) / (1024 * 1024), 2)
            daily_growth_kb = round(forecast["daily_growth_bytes"] / 1024, 1)

            runway_str = f"Estimated **{forecast['days_to_quota']} days**" if forecast.get("days_to_quota") is not None else "Unlimited runway (under quota threshold)"

            return {
                "response": (
                    f"### 🔮 Predictive 30-Day Storage Consumption Outlook\n\n"
                    f"*Statistical forecast calculated using linear regression; not an actual measurement.*\n\n"
                    f"- **Current Cloud Footprint:** **{cur_mb} MB**\n"
                    f"- **Daily Growth Velocity:** **+{daily_growth_kb} KB/day**\n"
                    f"- **+7 Days Projected:** {d7_mb} MB\n"
                    f"- **+14 Days Projected:** {d14_mb} MB\n"
                    f"- **+30 Days Projected:** **{d30_mb} MB**\n"
                    f"- **Time Until Storage Limit:** {runway_str}\n"
                    f"- **Forecast Model & Confidence:** `{forecast.get('growth_model', 'baseline')}` (Confidence: **{forecast.get('forecast_confidence', 'Normal')}**)\n\n"
                    f"Deduplication and incremental change detection ensure unmodified files do not consume additional cloud storage space."
                    f"{self.FALLBACK_NOTICE}"
                ),
                "data": forecast,
                "action_card": None
            }

        # 8C. Folder Cadence Recommendations ("Which folders need more frequent backups?")
        if any(w in p for w in ["which folders need", "folders need more frequent", "more frequent backups", "folder cadence", "which folders", "frequency recommendations"]):
            from backend.app.services.analytics_service import get_folder_cadence_recommendations
            cadence_data = get_folder_cadence_recommendations(user_id, db)
            folders = cadence_data.get("folder_recommendations", [])
            if not folders:
                return {
                    "response": (
                        "### 📁 Folder Cadence Analysis\n\n"
                        "No active backup plan source folders are configured. Create a backup plan to start tracking file modification velocity."
                        f"{self.FALLBACK_NOTICE}"
                    ),
                    "data": cadence_data,
                    "action_card": None
                }

            lines = ["### 📁 Data-Grounded Folder Cadence Recommendations\n"]
            for f in folders:
                lines.append(f"- **`{f['directory_path']}`** ({f['plan_name']}):")
                lines.append(f"  * **Recommended Schedule:** **{f['recommended_schedule']}** (Current: `{f.get('current_schedule_type', 'manual')}`)")
                lines.append(f"  * **Justification:** {f['reason']}")
            lines.append("\n*To apply an updated schedule, adjust the interval or cron in the **Scheduler** tab.*")
            lines.append(self.FALLBACK_NOTICE)
            return {
                "response": "\n".join(lines),
                "data": cadence_data,
                "action_card": None
            }

        # 8D. Prioritized Remediation ("What should I fix first?")
        if any(w in p for w in ["what should i fix first", "fix first", "what to fix first", "top priority", "priorities", "what needs attention"]):
            from backend.app.services.analytics_service import generate_weekly_report
            rep = generate_weekly_report(user_id, db)
            actions = rep.get("prioritized_actions", [])

            lines = ["### 🎯 Prioritized System Action Plan\n", "Ranked in order of critical impact:\n"]
            for idx, a in enumerate(actions, 1):
                lines.append(f"**{idx}. [{a['priority']}] {a['title']}**\n   {a['action']}\n")
            lines.append(self.FALLBACK_NOTICE)
            return {
                "response": "\n".join(lines),
                "data": rep,
                "action_card": None
            }

        # 8E. Storage Usage Changes ("How has my storage usage changed?")
        if any(w in p for w in ["how has my storage usage changed", "storage usage changed", "storage changed", "storage delta", "how has my storage"]):
            from backend.app.services.analytics_service import get_analytics_overview, generate_weekly_report
            rep = generate_weekly_report(user_id, db)
            sc = rep.get("storage_changes", {})
            delta_mb = round(sc.get("storage_delta_7d_bytes", 0) / (1024 * 1024), 2)
            cur_mb = round(sc.get("physical_stored_bytes", 0) / (1024 * 1024), 2)
            saved_mb = round(sc.get("bytes_saved", 0) / (1024 * 1024), 2)

            return {
                "response": (
                    f"### 📈 Storage Evolution Analysis\n\n"
                    f"- **Current Physical Stored:** **{cur_mb} MB**\n"
                    f"- **7-Day Net Storage Change:** **{('+' if delta_mb >= 0 else '')}{delta_mb} MB**\n"
                    f"- **Bandwidth Saved via Deduplication:** **{saved_mb} MB** ({sc.get('deduplication_ratio', 1.0)}x multiplier)\n"
                    f"- **Estimated Monthly Cloud Cost:** **${sc.get('estimated_monthly_cost_usd', 0.0)}/mo**\n\n"
                    f"Incremental delta block chunking and zero-byte deduplication ensure only modified data consumes additional cloud quota."
                    f"{self.FALLBACK_NOTICE}"
                ),
                "data": sc,
                "action_card": None
            }

        # 8F1. Encryption Status Query ("Are my backups encrypted?")
        if any(w in p for w in ["are my backups encrypted", "is encryption enabled", "are files encrypted", "backup encryption"]):
            enc_objects = db.query(StorageObject).filter(StorageObject.user_id == user_id, StorageObject.is_encrypted == True).count()
            unenc_objects = db.query(StorageObject).filter(StorageObject.user_id == user_id, StorageObject.is_encrypted == False).count()
            plans = db.query(BackupPlan).filter(BackupPlan.user_id == user_id, BackupPlan.is_active == True).all()
            all_enc = len(plans) > 0 and all(p.encryption_enabled for p in plans)
            u = db.query(User).filter(User.id == user_id).first()
            key_ver = getattr(u, "current_key_version", 1) or 1

            lines = ["### 🔐 Zero-Trust Encryption Status\n"]
            if all_enc and unenc_objects == 0:
                lines.append(f"✅ **All backups are encrypted with AES-256-GCM Envelope Encryption.**")
            elif enc_objects > 0:
                lines.append(f"ℹ️ **Partially Encrypted:** **{enc_objects:,} encrypted objects** and **{unenc_objects:,} unencrypted objects**.")
            else:
                lines.append("⚠️ **No encrypted backup objects found.** Ensure 'Enable Encryption' is checked in your backup plans.")

            lines.append(f"- **Algorithm:** AES-256-GCM with hardware-accelerated authenticated tags (128-bit)")
            lines.append(f"- **Key Architecture:** 2-tier Envelope Encryption (PBKDF2 KEK derivation + unique random 256-bit DEK per file)")
            lines.append(f"- **Key Encryption Key Version:** `v{key_ver}` (Key rotation supported without losing older backups)")
            lines.append(f"- **Nonce Safety:** 96-bit cryptographically secure random nonce generated per payload; nonces are never reused.")
            lines.append(self.FALLBACK_NOTICE)
            return {
                "response": "\n".join(lines),
                "data": {"encrypted_objects": enc_objects, "unencrypted_objects": unenc_objects, "key_version": key_ver, "all_plans_encrypted": all_enc},
                "action_card": None
            }

        # 8F2. MFA Status Query ("Is MFA enabled?")
        if any(w in p for w in ["is mfa enabled", "is multi-factor enabled", "is 2fa enabled", "mfa status", "do i have mfa"]):
            u = db.query(User).filter(User.id == user_id).first()
            mfa_on = getattr(u, "mfa_enabled", False) if u else False
            rec_codes_left = db.query(MFARecoveryCode).filter(MFARecoveryCode.user_id == user_id, MFARecoveryCode.is_used == False).count()

            lines = ["### 📱 Multi-Factor Authentication (MFA) Status\n"]
            if mfa_on:
                lines.append("✅ **Multi-Factor Authentication is ACTIVE on your account.**")
                lines.append(f"- **Protocol:** RFC 6238 Time-Based One-Time Password (TOTP, 30s window)")
                lines.append(f"- **Authenticator Compatibility:** Google Authenticator, Microsoft Authenticator, Authy")
                lines.append(f"- **One-Time Recovery Codes Remaining:** **{rec_codes_left} codes**")
                lines.append("- **Brute-Force Shield:** Rate limiting active (temporary 15-minute account lockout after 5 consecutive failed attempts).")
            else:
                lines.append("⚠️ **MFA is currently DISABLED.** Your account relies solely on single-factor password authentication.")
                lines.append("- To protect against credential theft, go to the **Security Center** and click **Set Up MFA** to pair your mobile authenticator app.")

            lines.append(self.FALLBACK_NOTICE)
            return {
                "response": "\n".join(lines),
                "data": {"mfa_enabled": mfa_on, "recovery_codes_remaining": rec_codes_left},
                "action_card": None
            }

        # 8F3. Protected Snapshots Query ("Which snapshots are protected?")
        if any(w in p for w in ["which snapshots are protected", "protected snapshots", "which snapshots are locked", "locked snapshots"]):
            locked_snaps = db.query(Snapshot).filter(Snapshot.user_id == user_id, Snapshot.is_locked == True).order_by(Snapshot.created_at.desc()).all()
            lines = ["### 🔒 WORM Protected Snapshots\n"]
            if not locked_snaps:
                lines.append("ℹ️ **No snapshots are currently protected by WORM retention locks.**")
                lines.append("Locking clean baseline snapshots ensures that ransomware or unauthorized deletion requests cannot modify or destroy your recovery points.")
            else:
                lines.append(f"CloudVault is currently protecting **{len(locked_snaps)} snapshot(s)** with immutable retention:\n")
                for s in locked_snaps:
                    dt = s.created_at.strftime("%Y-%m-%d %H:%M UTC") if s.created_at else "Unknown"
                    expiry = s.lock_until.strftime("%Y-%m-%d %H:%M UTC") if s.lock_until else "Permanent"
                    mode = getattr(s, "retention_mode", "SIMULATED")
                    lock_type = getattr(s, "provider_lock_type", "MOCK_SIMULATED")
                    badge = f"[{mode}: {lock_type}]"
                    lines.append(f"- **Snapshot #{s.snapshot_number} ({s.name})**: Locked until `{expiry}` {badge}")

            lines.append(self.FALLBACK_NOTICE)
            return {
                "response": "\n".join(lines),
                "data": {"protected_snapshots_count": len(locked_snaps)},
                "action_card": None
            }

        # 8F4. Retention Expiry Query ("When does a retention lock expire?")
        if any(w in p for w in ["when does a retention lock expire", "when does retention lock expire", "retention lock expire", "when does lock expire", "lock expire"]):
            locked_snaps = db.query(Snapshot).filter(Snapshot.user_id == user_id, Snapshot.is_locked == True, Snapshot.lock_until != None).order_by(Snapshot.lock_until.asc()).all()
            from datetime import datetime
            now = datetime.utcnow()
            lines = ["### ⏳ WORM Retention Expiry Schedule\n"]
            if not locked_snaps:
                lines.append("ℹ️ **There are no active retention lock expiries scheduled.** None of your snapshots currently carry a timed WORM retention policy.")
            else:
                lines.append("Upcoming retention lock expiries for protected snapshots:\n")
                for s in locked_snaps:
                    exp_dt = s.lock_until
                    if exp_dt > now:
                        remaining_days = (exp_dt - now).days
                        remaining_hrs = int((exp_dt - now).total_seconds() // 3600)
                        time_str = f"**{remaining_days} days** ({remaining_hrs} hours) remaining"
                    else:
                        time_str = "**Expired** (Ready for policy refresh or standard deletion)"
                    mode = getattr(s, "retention_mode", "SIMULATED")
                    lines.append(f"- **Snapshot #{s.snapshot_number} ({s.name})**: Expires on `{exp_dt.strftime('%Y-%m-%d %H:%M UTC')}` — {time_str} [{mode}]")

            lines.append(self.FALLBACK_NOTICE)
            return {
                "response": "\n".join(lines),
                "data": {"locked_snapshots_count": len(locked_snaps)},
                "action_card": None
            }

        # 8F5. Audit Trail Integrity Query ("Has my audit trail been tampered with?")
        if any(w in p for w in ["has my audit trail been tampered with", "audit trail tampered", "has audit been tampered", "audit tampered", "verify audit trail", "audit log integrity"]):
            audit_result = verify_audit_log_chain(user_id=user_id, db=db)
            lines = ["### ⛓️ Audit Trail Tamper-Evidence Verification\n"]
            if audit_result["is_valid"]:
                lines.append(f"✅ **Audit Trail Integrity Verified: 100% Intact.**")
                lines.append(f"- **Total Blocks Verified:** **{audit_result['total_entries']} entries**")
                lines.append(f"- **Genesis Linkage:** Valid genesis block anchor")
                lines.append(f"- **Hash Algorithm:** SHA-256 sequential block chain (`prev_hash` $\\parallel$ entry payload $\\rightarrow$ `current_hash`)")
                lines.append(f"- **Tamper Detection Status:** **0 broken links**, 0 modified records detected.")
                lines.append(f"\n*Note: Cryptographic hash chaining provides mathematically provable tamper-evidence within the database, proving historical ordering and exposing any modifications.*")
            else:
                lines.append(f"🚨 **WARNING: Audit Trail Discrepancy Detected!**")
                lines.append(f"- **Error:** {audit_result.get('error_message')}")
                lines.append(f"- **Broken Block ID:** `{audit_result.get('broken_entry_id')}`")
                lines.append(f"- **Verified Blocks Prior to Break:** {audit_result['verified_entries']} of {audit_result['total_entries']}")

            lines.append(self.FALLBACK_NOTICE)
            return {
                "response": "\n".join(lines),
                "data": audit_result,
                "action_card": None
            }

        # 8F6. Restore Safety Query ("Are my files safe to restore?")
        if any(w in p for w in ["are my files safe to restore", "safe to restore", "is it safe to restore", "restore safety"]):
            active_alerts = db.query(RansomwareAlert).filter(RansomwareAlert.user_id == user_id, RansomwareAlert.status == "ACTIVE").all()
            quarantined = [a for a in active_alerts if a.alert_level == "QUARANTINED"]
            latest_snap = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).first()
            latest_drill = db.query(DRDrill).filter(DRDrill.user_id == user_id).order_by(DRDrill.created_at.desc()).first()

            lines = ["### 🛡️ File Restoration Safety Assessment\n"]
            if quarantined:
                lines.append(f"🚨 **CAUTION: Active Ransomware Quarantine in Effect!**")
                lines.append(f"There is an active quarantine alert on your account (Risk Score: {quarantined[0].risk_score}/100).")
                lines.append(f"- **Do not restore recent unverified files to primary work folders.**")
                lines.append(f"- Only restore from clean snapshots created **before** `{quarantined[0].created_at.strftime('%Y-%m-%d %H:%M UTC')}`.")
            elif active_alerts:
                lines.append(f"⚠️ **Warning:** A suspicious activity alert ({active_alerts[0].alert_level}) is active.")
                lines.append("Verify file checksums in the Security Center before executing system-level restores.")
            else:
                lines.append("✅ **Files are verified safe to restore.**")
                lines.append("- **Ransomware Threat Level:** 0 active threats detected.")
                if latest_drill and latest_drill.status == "PASSED":
                    lines.append(f"- **Synthetic DR Drill:** Latest drill **PASSED** ({latest_drill.files_tested} files, bit-for-bit SHA-256 match verified).")
                if latest_snap:
                    lines.append(f"- **Recommended Baseline Snapshot:** **#{latest_snap.snapshot_number} ({latest_snap.name})**.")

            lines.append(self.FALLBACK_NOTICE)
            return {
                "response": "\n".join(lines),
                "data": {"active_alerts_count": len(active_alerts), "quarantined_count": len(quarantined)},
                "action_card": None
            }

        # 8F7. Security Improvements Query ("What security improvements do I need?")
        if any(w in p for w in ["what security improvements", "security improvements", "how to improve security", "security checklist", "what security risks", "security risks should i address", "security risks", "vulnerabilities to address"]):
            u = db.query(User).filter(User.id == user_id).first()
            mfa_on = getattr(u, "mfa_enabled", False) if u else False
            active_alerts = db.query(RansomwareAlert).filter(RansomwareAlert.user_id == user_id, RansomwareAlert.status == "ACTIVE").count()
            unenc_plans = db.query(BackupPlan).filter(BackupPlan.user_id == user_id, BackupPlan.encryption_enabled == False).count()
            unlocked_snaps = db.query(Snapshot).filter(Snapshot.user_id == user_id, Snapshot.is_locked == False).count()
            total_snaps = db.query(Snapshot).filter(Snapshot.user_id == user_id).count()
            dr_passed = db.query(DRDrill).filter(DRDrill.user_id == user_id, DRDrill.status == "PASSED").count() > 0

            lines = ["### 🛡️ Comprehensive Cyber Resilience Checklist\n"]
            # 1. MFA
            if not mfa_on:
                lines.append("1. **⚠️ Enable Multi-Factor Authentication (High Priority):** Your account is currently single-factor. Enable TOTP MFA in the Security tab.")
            else:
                lines.append("1. **✅ Multi-Factor Authentication:** TOTP RFC 6238 active with brute-force rate limiting.")

            # 2. Encryption
            if unenc_plans > 0:
                lines.append(f"2. **⚠️ Enable Zero-Trust Encryption:** {unenc_plans} backup plan(s) have AES-256-GCM encryption turned off.")
            else:
                lines.append("2. **✅ AES-256-GCM Envelope Encryption:** All active backup plans are configured with envelope encryption.")

            # 3. WORM Immutability
            if unlocked_snaps > 0 and total_snaps > 0:
                lines.append(f"3. **ℹ️ Protect Clean Snapshots with WORM:** {unlocked_snaps} snapshot(s) lack immutable retention locks.")
            elif total_snaps == 0:
                lines.append("3. **ℹ️ Snapshot Retention:** Execute your first backup plan and lock the baseline snapshot.")
            else:
                lines.append("3. **✅ WORM Retention Locks:** Baseline snapshots are protected against ransomware tampering.")

            # 4. DR Drill
            if not dr_passed:
                lines.append("4. **⚠️ Run Synthetic Recovery Drill:** No recent synthetic DR drill has been verified. Run a drill in the DR Center to prove bit-level recoverability.")
            else:
                lines.append("4. **✅ Recovery Verification:** Synthetic recovery drills have verified SHA-256 integrity.")

            # 5. Ransomware Shield
            if active_alerts > 0:
                lines.append(f"5. **🚨 Resolve Security Alerts:** **{active_alerts} alert(s)** pending resolution in the Security Center.")
            else:
                lines.append("5. **✅ Ransomware Monitoring:** Real-time Shannon entropy and velocity defense is active.")

            lines.append("\n*All improvements can be configured directly from the **Security & Ransomware Shield** and **Disaster Recovery** tabs.*")
            lines.append(self.FALLBACK_NOTICE)
            return {
                "response": "\n".join(lines),
                "data": {
                    "mfa_enabled": mfa_on,
                    "active_alerts": active_alerts,
                    "unencrypted_plans": unenc_plans,
                    "unlocked_snapshots": unlocked_snaps,
                    "dr_passed": dr_passed
                },
                "action_card": None
            }

        # 8G. General Recommendations Query
        if any(w in p for w in ["recommend", "improve", "advice", "suggestion", "best practice", "improve my backup protection"]):
            data = tool_get_backup_recommendations(user_id, db)
            recs = data["recommendations"]
            lines = ["### 💡 Intelligent Backup Recommendations\n"]
            for r in recs:
                lines.append(f"- {r}")
            lines.append(self.FALLBACK_NOTICE)
            return {
                "response": "\n".join(lines),
                "data": data,
                "action_card": None
            }

        # 9. Controlled Action: Propose File Restore
        if any(w in p for w in ["restore a file", "restore my file", "restore file", "restore", "recover file", "bring back"]):
            # Extract potential filename if given (e.g., 'restore file foo.txt' or 'restore .gitignore')
            match = re.search(r'restore\s+(?:file\s+)?([a-zA-Z0-9_\-\.\/]+)', prompt, re.IGNORECASE)
            target_file = match.group(1).strip() if match else None
            if target_file and target_file.lower() in ["a", "my", "the", "file", "snapshot", "now", "please"]:
                target_file = None

            action_proposal = tool_propose_restore_file(
                user_id=user_id,
                snapshot_id=None,
                relative_path=target_file,
                destination_dir="./restored",
                db=db
            )

            if action_proposal.get("status") == "error":
                return {
                    "response": (
                        f"### ⚠️ Restoration Unavailable\n\n"
                        f"{action_proposal.get('message')}"
                        f"{self.FALLBACK_NOTICE}"
                    ),
                    "data": None,
                    "action_card": None
                }

            proposed = action_proposal["proposed_action"]
            file_kb = round(proposed.get("file_size", 0) / 1024, 2)
            return {
                "response": (
                    f"### 📥 File Restoration Request Prepared\n\n"
                    f"I have prepared an authorized point-in-time restoration for **`{proposed['file_name']}`**.\n\n"
                    f"- **Source Snapshot:** #{proposed['snapshot_number']} (*{proposed['snapshot_name']}*)\n"
                    f"- **Relative Path:** `{proposed['relative_path']}`\n"
                    f"- **File Size:** {file_kb} KB\n"
                    f"- **Target Destination:** `{proposed['destination_dir']}`\n"
                    f"- **Cryptographic Integrity:** Pre-restore and post-restore SHA-256 verification active.\n\n"
                    f"Under CloudVault zero-trust safety policy, sensitive restore operations require explicit human authorization. "
                    f"Please confirm execution using the card below:"
                    f"{self.FALLBACK_NOTICE}"
                ),
                "data": proposed,
                "action_card": action_proposal
            }

        # 10. Controlled Action: Propose Verify Snapshot
        if any(w in p for w in ["verify snapshot", "verify backup", "check integrity", "recovery drill", "verify recovery"]):
            action_proposal = tool_propose_verify_snapshot(user_id=user_id, snapshot_id=None, db=db)
            if action_proposal.get("status") == "error":
                return {
                    "response": f"Unable to prepare verification: {action_proposal.get('message')}{self.FALLBACK_NOTICE}",
                    "data": None,
                    "action_card": None
                }
            return {
                "response": (
                    "### 🔍 Snapshot Integrity Drill Prepared\n\n"
                    "I have prepared a non-destructive synthetic recovery drill to mathematically verify SHA-256 hash fidelity "
                    "for your latest snapshot.\n\n"
                    "Please confirm execution to start the verification drill:"
                    f"{self.FALLBACK_NOTICE}"
                ),
                "data": None,
                "action_card": action_proposal
            }

        # 11. Controlled Action: Propose Trigger Backup
        if any(w in p for w in ["run backup", "trigger backup", "create backup", "take a backup", "backup now"]):
            action_proposal = tool_propose_trigger_backup(user_id, None, db)
            if action_proposal.get("status") == "error":
                return {
                    "response": f"Unable to prepare backup: {action_proposal.get('message')}{self.FALLBACK_NOTICE}",
                    "data": None,
                    "action_card": None
                }
            return {
                "response": (
                    "### ⚡ Backup Request Prepared\n\n"
                    "I have prepared an on-demand backup execution request for your active plan. "
                    "For security and audit compliance, please review and confirm the action card below:"
                    f"{self.FALLBACK_NOTICE}"
                ),
                "data": None,
                "action_card": action_proposal
            }

        # 12. Controlled Action: Propose Lock Snapshot
        if any(w in p for w in ["lock snapshot", "immutable", "worm lock"]):
            latest_snap = db.query(Snapshot).filter(Snapshot.user_id == user_id).order_by(Snapshot.created_at.desc()).first()
            if not latest_snap:
                return {
                    "response": f"No snapshots available to lock. Please run a backup first.{self.FALLBACK_NOTICE}",
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
                    f"{self.FALLBACK_NOTICE}"
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
                "- *'Which backups failed?'*\n"
                "- *'How much storage have I saved through deduplication?'*\n"
                "- *'Which files have not been backed up recently?'*\n"
                "- *'Is my backup system healthy?'*\n"
                "- *'How can I improve my backup protection?'*\n"
                "- *'Restore a file.'*\n"
                "- *'Verify a snapshot.'*\n"
                "- *'Create a backup.'*\n"
                "- *'Lock a snapshot with WORM retention.'*"
                f"{self.FALLBACK_NOTICE}"
            ),
            "data": None,
            "action_card": None
        }


class ExternalLLMProvider(BaseAIProvider):
    """
    External LLM Provider connecting to OpenAI, Gemini, or an OpenAI-compatible API.
    Uses ground-truth metadata injected as context and gracefully falls back to
    RuleBasedLocalLLMProvider if external service is unreachable or credentials are unconfigured.
    """

    def __init__(self, api_key: str, model: str = None, base_url: str = None):
        self.api_key = api_key
        self.model = model or os.environ.get("LLM_MODEL", "gpt-4o-mini")
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.fallback = RuleBasedLocalLLMProvider()

    def process_query(self, user_id: str, prompt: str, db: Session) -> Dict[str, Any]:
        p = prompt.strip().lower()

        # If user asks for an explicit action, use safe deterministic rule tool proposals
        if any(w in p for w in ["restore", "recover", "lock", "trigger backup", "create backup", "verify"]):
            logger.info("Routing action proposal to deterministic security governor.")
            return self.fallback.process_query(user_id, prompt, db)

        # For informational queries, gather grounded metadata
        try:
            prot_summary = tool_get_protected_files_summary(user_id, db)
            storage_savings = tool_get_storage_savings(user_id, db)
            health = tool_check_system_health(user_id, db)

            system_context = (
                f"You are the CloudVault AI Copilot. CloudVault is a secure cloud backup and disaster recovery platform. "
                f"Ground your answer strictly in the user's actual backup data: "
                f"- Protected Files: {prot_summary['protected_files_count']} across {prot_summary['active_plans_count']} plans\n"
                f"- Snapshots: {prot_summary['total_snapshots_count']}\n"
                f"- Logical Data: {round(storage_savings['logical_uncompressed_bytes'] / (1024*1024), 2)} MB\n"
                f"- Physical Stored: {round(storage_savings['physical_stored_bytes'] / (1024*1024), 2)} MB\n"
                f"- Space Saved: {round(storage_savings['bytes_saved'] / (1024*1024), 2)} MB ({storage_savings['savings_percentage']}%)\n"
                f"- System Health Score: {health['health_score']}/100 ({health['health_status']})\n"
                f"Answer concisely with markdown formatting."
            )

            req_payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_context},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2
            }

            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }

            req = urllib_request.Request(
                f"{self.base_url}/chat/completions",
                data=json.dumps(req_payload).encode("utf-8"),
                headers=headers,
                method="POST"
            )

            with urllib_request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                reply = data["choices"][0]["message"]["content"]
                reply += f"\n\n*(🤖 External LLM Engine: {self.model})*"
                return {
                    "response": reply,
                    "data": {"model": self.model},
                    "action_card": None
                }

        except Exception as e:
            logger.warning(f"External LLM invocation failed or timed out ({e}). Falling back to Local Rule-Based Engine.")
            result = self.fallback.process_query(user_id, prompt, db)
            result["response"] += f"\n\n> *[Notice: External LLM was unavailable ({e.__class__.__name__}). Used Local Semantic Fallback.]*"
            return result


def get_ai_provider() -> BaseAIProvider:
    """
    Factory returning configured AI Provider.
    If external LLM credentials are provided and AI_PROVIDER is set to 'llm',
    returns ExternalLLMProvider. Otherwise, defaults to the deterministic,
    offline, zero-cost RuleBasedLocalLLMProvider.
    """
    ai_provider_mode = os.environ.get("AI_PROVIDER", getattr(settings, "AI_PROVIDER", "local_rules")).lower()
    api_key = os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY") or os.environ.get("GEMINI_API_KEY")

    if ai_provider_mode == "llm" and api_key:
        return ExternalLLMProvider(api_key=api_key)

    return RuleBasedLocalLLMProvider()
