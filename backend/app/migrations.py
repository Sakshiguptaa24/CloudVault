"""
CloudVault 2.0 Engine-Agnostic Migration Engine
Supports SQLite (local development) and PostgreSQL (production deployment).
Idempotent, non-destructive, with schema version tracking.
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, Union, List, Dict, Any

from sqlalchemy import create_engine, inspect, text, Table, Column, String, DateTime, MetaData
from sqlalchemy.engine import Engine

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.app.config import BASE_DIR, settings
from backend.app.database import Base, engine as default_engine
import backend.app.models  # Ensure all SQLAlchemy models are registered


MIGRATION_VERSION = "2026_03_01_phase7_hardening"

# Column definitions for existing tables that may have been created in earlier phases.
# Formatted to be ANSI SQL compliant across both SQLite and PostgreSQL.
TABLE_COLUMN_SPECS: Dict[str, List[Dict[str, Any]]] = {
    "users": [
        {"name": "mfa_secret", "sqlite": "VARCHAR(64)", "postgres": "VARCHAR(64)"},
        {"name": "mfa_enabled", "sqlite": "BOOLEAN DEFAULT 0", "postgres": "BOOLEAN DEFAULT FALSE"},
        {"name": "encryption_salt", "sqlite": "VARCHAR(64)", "postgres": "VARCHAR(64)"},
        {"name": "current_key_version", "sqlite": "INTEGER DEFAULT 1", "postgres": "INTEGER DEFAULT 1"},
        {"name": "mfa_failed_attempts", "sqlite": "INTEGER DEFAULT 0", "postgres": "INTEGER DEFAULT 0"},
        {"name": "mfa_locked_until", "sqlite": "DATETIME", "postgres": "TIMESTAMP WITH TIME ZONE"},
    ],
    "backup_plans": [
        {"name": "encryption_enabled", "sqlite": "BOOLEAN DEFAULT 1", "postgres": "BOOLEAN DEFAULT TRUE"},
        {"name": "immutable_lock_days", "sqlite": "INTEGER DEFAULT 0", "postgres": "INTEGER DEFAULT 0"},
    ],
    "snapshots": [
        {"name": "is_immutable", "sqlite": "BOOLEAN DEFAULT 0", "postgres": "BOOLEAN DEFAULT FALSE"},
        {"name": "lock_until", "sqlite": "DATETIME", "postgres": "TIMESTAMP WITH TIME ZONE"},
        {"name": "verification_status", "sqlite": "VARCHAR(20) DEFAULT 'UNVERIFIED'", "postgres": "VARCHAR(20) DEFAULT 'UNVERIFIED'"},
        {"name": "verified_at", "sqlite": "DATETIME", "postgres": "TIMESTAMP WITH TIME ZONE"},
        {"name": "retention_mode", "sqlite": "VARCHAR(30) DEFAULT 'SIMULATED'", "postgres": "VARCHAR(30) DEFAULT 'SIMULATED'"},
        {"name": "provider_lock_type", "sqlite": "VARCHAR(50) DEFAULT 'MOCK_SIMULATED'", "postgres": "VARCHAR(50) DEFAULT 'MOCK_SIMULATED'"},
        {"name": "retention_period_days", "sqlite": "INTEGER DEFAULT 0", "postgres": "INTEGER DEFAULT 0"},
    ],
    "storage_objects": [
        {"name": "is_encrypted", "sqlite": "BOOLEAN DEFAULT 0", "postgres": "BOOLEAN DEFAULT FALSE"},
        {"name": "encryption_algo", "sqlite": "VARCHAR(30) DEFAULT 'AES-256-GCM'", "postgres": "VARCHAR(30) DEFAULT 'AES-256-GCM'"},
        {"name": "encryption_nonce", "sqlite": "VARCHAR(64)", "postgres": "VARCHAR(64)"},
        {"name": "encrypted_dek", "sqlite": "TEXT", "postgres": "TEXT"},
        {"name": "dek_nonce", "sqlite": "VARCHAR(64)", "postgres": "VARCHAR(64)"},
        {"name": "key_version", "sqlite": "INTEGER DEFAULT 1", "postgres": "INTEGER DEFAULT 1"},
        {"name": "aad_tag", "sqlite": "VARCHAR(255)", "postgres": "VARCHAR(255)"},
    ],
    "audit_logs": [
        {"name": "severity", "sqlite": "VARCHAR(20) DEFAULT 'INFO'", "postgres": "VARCHAR(20) DEFAULT 'INFO'"},
        {"name": "user_agent", "sqlite": "VARCHAR(255) DEFAULT ''", "postgres": "VARCHAR(255) DEFAULT ''"},
        {"name": "details", "sqlite": "TEXT DEFAULT '{}'", "postgres": "TEXT DEFAULT '{}'"},
        {"name": "prev_hash", "sqlite": "VARCHAR(64) DEFAULT ''", "postgres": "VARCHAR(64) DEFAULT ''"},
        {"name": "current_hash", "sqlite": "VARCHAR(64) DEFAULT ''", "postgres": "VARCHAR(64) DEFAULT ''"},
    ],
    "dr_drills": [
        {"name": "drill_type", "sqlite": "VARCHAR(50) DEFAULT 'FULL_SNAPSHOT'", "postgres": "VARCHAR(50) DEFAULT 'FULL_SNAPSHOT'"},
        {"name": "drill_scope", "sqlite": "VARCHAR(255)", "postgres": "VARCHAR(255)"},
        {"name": "verification_report", "sqlite": "TEXT", "postgres": "TEXT"},
    ]
}


def get_target_engine(engine_or_url: Optional[Union[Engine, str]] = None, db_path: Optional[str] = None) -> Engine:
    """Resolve target SQLAlchemy Engine from argument, db_path, or default application engine."""
    if engine_or_url is not None:
        if isinstance(engine_or_url, Engine):
            return engine_or_url
        return create_engine(engine_or_url)
    
    if db_path is not None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        return create_engine(f"sqlite:///{db_path}")

    return default_engine


def init_migration_tracking(engine: Engine) -> None:
    """Create schema_migrations version table if it doesn't already exist."""
    with engine.begin() as conn:
        dialect = engine.dialect.name
        if dialect == "sqlite":
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version VARCHAR(100) PRIMARY KEY,
                    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    dialect VARCHAR(30)
                )
            """))
        else:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version VARCHAR(100) PRIMARY KEY,
                    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    dialect VARCHAR(30)
                )
            """))


def is_migration_applied(engine: Engine, version: str) -> bool:
    """Check if the given version is recorded in schema_migrations."""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT version FROM schema_migrations WHERE version = :ver"),
                {"ver": version}
            ).fetchone()
            return result is not None
    except Exception:
        return False


def record_migration_applied(engine: Engine, version: str) -> None:
    """Record successfully applied migration in schema_migrations table."""
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO schema_migrations (version, dialect) VALUES (:ver, :dia)"),
            {"ver": version, "dia": engine.dialect.name}
        )


def run_migrations(
    engine_or_url: Optional[Union[Engine, str]] = None,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Run non-destructive, engine-independent schema migrations.
    Safely creates all missing tables and adds missing columns to existing tables.
    Works identically on SQLite and PostgreSQL.
    """
    engine = get_target_engine(engine_or_url, db_path)
    dialect = engine.dialect.name
    print(f"Applying CloudVault 2.0 migrations to: {engine.url} (dialect: {dialect})")

    # 1. Initialize migration tracking table
    init_migration_tracking(engine)

    # 2. Idempotently create any tables defined in SQLAlchemy models that don't exist yet
    Base.metadata.create_all(bind=engine)

    # 3. Inspect existing tables and apply missing columns non-destructively
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    columns_added = []
    with engine.begin() as conn:
        for table_name, col_specs in TABLE_COLUMN_SPECS.items():
            if table_name in existing_tables:
                existing_cols = {col["name"] for col in inspector.get_columns(table_name)}
                for spec in col_specs:
                    col_name = spec["name"]
                    if col_name not in existing_cols:
                        type_str = spec["sqlite"] if dialect == "sqlite" else spec["postgres"]
                        sql = f"ALTER TABLE {table_name} ADD COLUMN {col_name} {type_str}"
                        conn.execute(text(sql))
                        columns_added.append(f"{table_name}.{col_name}")

    # 4. Record migration version
    if not is_migration_applied(engine, MIGRATION_VERSION):
        record_migration_applied(engine, MIGRATION_VERSION)

    result = {
        "status": "SUCCESS",
        "dialect": dialect,
        "migration_version": MIGRATION_VERSION,
        "columns_added": columns_added
    }
    print(f"Database migrations applied successfully! Columns added: {len(columns_added)}")
    return result


def generate_postgres_migration_sql() -> str:
    """
    Generate an offline pure PostgreSQL DDL script for enterprise DBA inspection
    and manual deployment without running against a live database.
    """
    statements = [
        "-- CloudVault 2.0 PostgreSQL Migration Script",
        f"-- Version: {MIGRATION_VERSION}",
        "-- Non-destructive schema evolution",
        "",
        "CREATE TABLE IF NOT EXISTS schema_migrations (",
        "    version VARCHAR(100) PRIMARY KEY,",
        "    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,",
        "    dialect VARCHAR(30)",
        ");",
        ""
    ]

    for table_name, col_specs in TABLE_COLUMN_SPECS.items():
        for spec in col_specs:
            col_name = spec["name"]
            type_str = spec["postgres"]
            statements.append(
                f"DO $$ BEGIN "
                f"IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='{table_name}' AND column_name='{col_name}') THEN "
                f"ALTER TABLE {table_name} ADD COLUMN {col_name} {type_str}; "
                f"END IF; END $$;"
            )

    statements.append("")
    statements.append(
        f"INSERT INTO schema_migrations (version, dialect) "
        f"VALUES ('{MIGRATION_VERSION}', 'postgresql') "
        f"ON CONFLICT (version) DO NOTHING;"
    )

    return "\n".join(statements)


if __name__ == "__main__":
    run_migrations()
