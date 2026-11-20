import sqlite3
import os
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.config import BASE_DIR, settings

def run_migrations(db_path: str = None):
    """
    Idempotent database migration script for CloudVault 2.0.
    Safely adds new columns to existing tables and creates new tables without data loss.
    """
    if db_path is None:
        db_path = str(BASE_DIR / "data" / "cloudvault.db")

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    def column_exists(table, column):
        cursor.execute(f"PRAGMA table_info({table})")
        columns = [row[1] for row in cursor.fetchall()]
        return column in columns

    def table_exists(table):
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
        return cursor.fetchone() is not None

    print(f"Applying CloudVault 2.0 migrations to: {db_path}")

    # 1. Update 'users' table
    if table_exists("users"):
        if not column_exists("users", "mfa_secret"):
            cursor.execute("ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(64)")
        if not column_exists("users", "mfa_enabled"):
            cursor.execute("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT 0")
        if not column_exists("users", "encryption_salt"):
            cursor.execute("ALTER TABLE users ADD COLUMN encryption_salt VARCHAR(64)")
        if not column_exists("users", "current_key_version"):
            cursor.execute("ALTER TABLE users ADD COLUMN current_key_version INTEGER DEFAULT 1")
        if not column_exists("users", "mfa_failed_attempts"):
            cursor.execute("ALTER TABLE users ADD COLUMN mfa_failed_attempts INTEGER DEFAULT 0")
        if not column_exists("users", "mfa_locked_until"):
            cursor.execute("ALTER TABLE users ADD COLUMN mfa_locked_until DATETIME")

    # 2. Update 'backup_plans' table
    if table_exists("backup_plans"):
        if not column_exists("backup_plans", "encryption_enabled"):
            cursor.execute("ALTER TABLE backup_plans ADD COLUMN encryption_enabled BOOLEAN DEFAULT 1")
        if not column_exists("backup_plans", "immutable_lock_days"):
            cursor.execute("ALTER TABLE backup_plans ADD COLUMN immutable_lock_days INTEGER DEFAULT 0")

    # 3. Update 'snapshots' table
    if table_exists("snapshots"):
        if not column_exists("snapshots", "is_immutable"):
            cursor.execute("ALTER TABLE snapshots ADD COLUMN is_immutable BOOLEAN DEFAULT 0")
        if not column_exists("snapshots", "lock_until"):
            cursor.execute("ALTER TABLE snapshots ADD COLUMN lock_until DATETIME")
        if not column_exists("snapshots", "verification_status"):
            cursor.execute("ALTER TABLE snapshots ADD COLUMN verification_status VARCHAR(20) DEFAULT 'UNVERIFIED'")
        if not column_exists("snapshots", "verified_at"):
            cursor.execute("ALTER TABLE snapshots ADD COLUMN verified_at DATETIME")
        if not column_exists("snapshots", "retention_mode"):
            cursor.execute("ALTER TABLE snapshots ADD COLUMN retention_mode VARCHAR(30) DEFAULT 'SIMULATED'")
        if not column_exists("snapshots", "provider_lock_type"):
            cursor.execute("ALTER TABLE snapshots ADD COLUMN provider_lock_type VARCHAR(50) DEFAULT 'MOCK_SIMULATED'")
        if not column_exists("snapshots", "retention_period_days"):
            cursor.execute("ALTER TABLE snapshots ADD COLUMN retention_period_days INTEGER DEFAULT 0")

    # 4. Update 'storage_objects' table
    if table_exists("storage_objects"):
        if not column_exists("storage_objects", "is_encrypted"):
            cursor.execute("ALTER TABLE storage_objects ADD COLUMN is_encrypted BOOLEAN DEFAULT 0")
        if not column_exists("storage_objects", "encryption_algo"):
            cursor.execute("ALTER TABLE storage_objects ADD COLUMN encryption_algo VARCHAR(30) DEFAULT 'AES-256-GCM'")
        if not column_exists("storage_objects", "encryption_nonce"):
            cursor.execute("ALTER TABLE storage_objects ADD COLUMN encryption_nonce VARCHAR(64)")
        if not column_exists("storage_objects", "encrypted_dek"):
            cursor.execute("ALTER TABLE storage_objects ADD COLUMN encrypted_dek TEXT")
        if not column_exists("storage_objects", "dek_nonce"):
            cursor.execute("ALTER TABLE storage_objects ADD COLUMN dek_nonce VARCHAR(64)")
        if not column_exists("storage_objects", "key_version"):
            cursor.execute("ALTER TABLE storage_objects ADD COLUMN key_version INTEGER DEFAULT 1")
        if not column_exists("storage_objects", "aad_tag"):
            cursor.execute("ALTER TABLE storage_objects ADD COLUMN aad_tag VARCHAR(255)")

    # 5. Create or update 'audit_logs' table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        event_type VARCHAR(50) NOT NULL,
        severity VARCHAR(20) DEFAULT 'INFO',
        ip_address VARCHAR(45) DEFAULT '',
        user_agent VARCHAR(255) DEFAULT '',
        details TEXT DEFAULT '{}',
        prev_hash VARCHAR(64) DEFAULT '',
        current_hash VARCHAR(64) DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    if table_exists("audit_logs"):
        if not column_exists("audit_logs", "severity"):
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN severity VARCHAR(20) DEFAULT 'INFO'")
        if not column_exists("audit_logs", "user_agent"):
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN user_agent VARCHAR(255) DEFAULT ''")
        if not column_exists("audit_logs", "details"):
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN details TEXT DEFAULT '{}'")
        if not column_exists("audit_logs", "prev_hash"):
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash VARCHAR(64) DEFAULT ''")
        if not column_exists("audit_logs", "current_hash"):
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN current_hash VARCHAR(64) DEFAULT ''")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at)")

    # 6. Create 'ai_action_requests' table (for replay prevention and action authorization)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ai_action_requests (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        action_type VARCHAR(50) NOT NULL,
        resource_id VARCHAR(100),
        proposed_payload TEXT NOT NULL,
        nonce VARCHAR(64) UNIQUE NOT NULL,
        is_consumed BOOLEAN DEFAULT 0,
        status VARCHAR(20) DEFAULT 'PENDING',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        executed_at DATETIME,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_nonce ON ai_action_requests(nonce)")

    # 7. Create 'ransomware_alerts' table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ransomware_alerts (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        plan_id VARCHAR(36),
        risk_score INTEGER NOT NULL,
        alert_level VARCHAR(20) NOT NULL,
        suspicious_files_count INTEGER DEFAULT 0,
        average_entropy FLOAT DEFAULT 0.0,
        matched_extensions TEXT DEFAULT '[]',
        details TEXT DEFAULT '{}',
        status VARCHAR(20) DEFAULT 'ACTIVE',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_user ON ransomware_alerts(user_id)")

    # 8. Create 'dr_drills' table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dr_drills (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        snapshot_id VARCHAR(36) NOT NULL,
        drill_type VARCHAR(50) DEFAULT 'FULL_SNAPSHOT',
        drill_scope VARCHAR(255),
        files_tested INTEGER NOT NULL,
        bytes_tested BIGINT NOT NULL,
        duration_seconds FLOAT NOT NULL,
        restoration_speed_mbps FLOAT DEFAULT 0.0,
        rpo_hours FLOAT DEFAULT 0.0,
        estimated_rto_minutes FLOAT DEFAULT 0.0,
        status VARCHAR(20) NOT NULL,
        error_details TEXT,
        verification_report TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
    )
    """)
    if table_exists("dr_drills"):
        if not column_exists("dr_drills", "drill_type"):
            cursor.execute("ALTER TABLE dr_drills ADD COLUMN drill_type VARCHAR(50) DEFAULT 'FULL_SNAPSHOT'")
        if not column_exists("dr_drills", "drill_scope"):
            cursor.execute("ALTER TABLE dr_drills ADD COLUMN drill_scope VARCHAR(255)")
        if not column_exists("dr_drills", "verification_report"):
            cursor.execute("ALTER TABLE dr_drills ADD COLUMN verification_report TEXT")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_dr_user ON dr_drills(user_id)")

    # 9. Create 'mfa_recovery_codes' table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        code_hash VARCHAR(255) NOT NULL,
        is_used BOOLEAN DEFAULT 0,
        used_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mfa_user ON mfa_recovery_codes(user_id)")

    # 10. Create 'recovery_operations' table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS recovery_operations (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        snapshot_id VARCHAR(36),
        operation_type VARCHAR(50) NOT NULL,
        target_path VARCHAR(1000),
        destination_path VARCHAR(1000),
        conflict_strategy VARCHAR(50) DEFAULT 'keep_both',
        status VARCHAR(20) DEFAULT 'SUCCESS',
        started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed_at DATETIME,
        duration_seconds FLOAT DEFAULT 0.0,
        rpo_hours FLOAT DEFAULT 0.0,
        files_restored INTEGER DEFAULT 0,
        bytes_restored BIGINT DEFAULT 0,
        throughput_mbps FLOAT DEFAULT 0.0,
        verification_report TEXT DEFAULT '{}',
        error_message TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rec_user ON recovery_operations(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rec_snapshot ON recovery_operations(snapshot_id)")

    conn.commit()
    conn.close()
    print("Database migrations applied successfully!")

if __name__ == "__main__":
    run_migrations()
