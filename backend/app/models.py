import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, BigInteger, Boolean, DateTime, ForeignKey, Text, Float
)
from sqlalchemy.orm import relationship
from backend.app.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=False)
    role = Column(String(20), default="user", nullable=False)
    quota_bytes = Column(BigInteger, default=5368709120, nullable=False) # 5 GB
    used_bytes = Column(BigInteger, default=0, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    mfa_secret = Column(String(64), nullable=True)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    encryption_salt = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
    backup_plans = relationship("BackupPlan", back_populates="user", cascade="all, delete-orphan")
    storage_objects = relationship("StorageObject", back_populates="user")
    snapshots = relationship("Snapshot", back_populates="user")
    backup_jobs = relationship("BackupJob", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    ai_actions = relationship("AIActionRequest", back_populates="user", cascade="all, delete-orphan")
    ransomware_alerts = relationship("RansomwareAlert", back_populates="user", cascade="all, delete-orphan")
    dr_drills = relationship("DRDrill", back_populates="user", cascade="all, delete-orphan")
    recovery_codes = relationship("MFARecoveryCode", back_populates="user", cascade="all, delete-orphan")


class Device(Base):
    __tablename__ = "devices"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    device_name = Column(String(100), nullable=False)
    machine_guid = Column(String(128), unique=True, index=True, nullable=False)
    os_type = Column(String(30), default="Windows", nullable=False)
    os_version = Column(String(50), default="", nullable=False)
    agent_version = Column(String(20), default="1.0.0", nullable=False)
    last_seen_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="devices")
    backup_plans = relationship("BackupPlan", back_populates="device")


class BackupPlan(Base):
    __tablename__ = "backup_plans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    device_id = Column(String(36), ForeignKey("devices.id"), nullable=True)
    plan_name = Column(String(100), nullable=False)
    source_directories = Column(Text, nullable=False)  # JSON array string e.g. '["C:\\Users\\..."]'
    exclusion_patterns = Column(Text, default="[]", nullable=False) # JSON array e.g. '["*.tmp", ".git"]'
    schedule_type = Column(String(20), default="manual", nullable=False) # manual, interval, daily
    schedule_expression = Column(String(100), default="3600", nullable=False) # seconds or HH:MM
    retention_days = Column(Integer, default=30, nullable=False)
    compression_algo = Column(String(20), default="gzip", nullable=False)
    encryption_enabled = Column(Boolean, default=True, nullable=False)
    immutable_lock_days = Column(Integer, default=0, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="backup_plans")
    device = relationship("Device", back_populates="backup_plans")
    snapshots = relationship("Snapshot", back_populates="plan", cascade="all, delete-orphan")
    jobs = relationship("BackupJob", back_populates="plan")
    ransomware_alerts = relationship("RansomwareAlert", back_populates="plan", cascade="all, delete-orphan")


class StorageObject(Base):
    __tablename__ = "storage_objects"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    sha256_hash = Column(String(64), unique=True, index=True, nullable=False)
    original_size = Column(BigInteger, nullable=False)
    compressed_size = Column(BigInteger, nullable=False)
    compression_algo = Column(String(20), default="gzip", nullable=False)
    is_encrypted = Column(Boolean, default=False, nullable=False)
    encryption_algo = Column(String(30), default="AES-256-GCM", nullable=False)
    encryption_nonce = Column(String(64), nullable=True)
    storage_provider = Column(String(20), default="mock", nullable=False) # mock, gcs, s3, azure
    storage_path = Column(String(255), nullable=False)
    storage_class = Column(String(20), default="STANDARD", nullable=False)
    ref_count = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="storage_objects")
    snapshot_files = relationship("SnapshotFile", back_populates="storage_object")


class Snapshot(Base):
    __tablename__ = "snapshots"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    plan_id = Column(String(36), ForeignKey("backup_plans.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    snapshot_number = Column(Integer, nullable=False)
    name = Column(String(150), nullable=False)
    snapshot_type = Column(String(20), default="incremental", nullable=False) # full, incremental
    total_files = Column(Integer, default=0, nullable=False)
    total_uncompressed_bytes = Column(BigInteger, default=0, nullable=False)
    total_stored_bytes = Column(BigInteger, default=0, nullable=False)
    is_locked = Column(Boolean, default=False, nullable=False)
    is_immutable = Column(Boolean, default=False, nullable=False)
    lock_until = Column(DateTime, nullable=True)
    verification_status = Column(String(20), default="UNVERIFIED", nullable=False)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    plan = relationship("BackupPlan", back_populates="snapshots")
    user = relationship("User", back_populates="snapshots")
    files = relationship("SnapshotFile", back_populates="snapshot", cascade="all, delete-orphan")
    dr_drills = relationship("DRDrill", back_populates="snapshot", cascade="all, delete-orphan")


class SnapshotFile(Base):
    __tablename__ = "snapshot_files"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    snapshot_id = Column(String(36), ForeignKey("snapshots.id"), nullable=False, index=True)
    storage_object_id = Column(String(36), ForeignKey("storage_objects.id"), nullable=False, index=True)
    relative_path = Column(String(1000), nullable=False, index=True)
    file_name = Column(String(255), nullable=False)
    file_extension = Column(String(50), default="")
    file_size = Column(BigInteger, nullable=False)
    modified_at = Column(DateTime, nullable=False)
    file_permissions = Column(String(20), default="644")
    is_deleted = Column(Boolean, default=False, nullable=False)

    snapshot = relationship("Snapshot", back_populates="files")
    storage_object = relationship("StorageObject", back_populates="snapshot_files")


class BackupJob(Base):
    __tablename__ = "backup_jobs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    plan_id = Column(String(36), ForeignKey("backup_plans.id"), nullable=True, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    status = Column(String(20), default="RUNNING", nullable=False) # RUNNING, SUCCESS, FAILED, INTERRUPTED
    trigger_type = Column(String(20), default="MANUAL", nullable=False) # MANUAL, SCHEDULED, WATCHER, AI
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    files_scanned = Column(Integer, default=0, nullable=False)
    files_uploaded = Column(Integer, default=0, nullable=False)
    files_deduplicated = Column(Integer, default=0, nullable=False)
    bytes_scanned = Column(BigInteger, default=0, nullable=False)
    bytes_uploaded = Column(BigInteger, default=0, nullable=False)
    bytes_deduplicated = Column(BigInteger, default=0, nullable=False)
    duration_seconds = Column(Integer, default=0, nullable=False)
    error_message = Column(Text, nullable=True)

    plan = relationship("BackupPlan", back_populates="jobs")
    user = relationship("User", back_populates="backup_jobs")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    event_type = Column(String(50), nullable=False) # AUTH, BACKUP, RESTORE, DELETE, AI_ACTION, SECURITY
    severity = Column(String(20), default="INFO", nullable=False) # INFO, WARNING, CRITICAL
    ip_address = Column(String(45), default="127.0.0.1")
    user_agent = Column(String(255), default="")
    details = Column(Text, default="{}") # JSON metadata
    prev_hash = Column(String(64), default="")
    current_hash = Column(String(64), default="")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    user = relationship("User", back_populates="audit_logs")


class AIActionRequest(Base):
    __tablename__ = "ai_action_requests"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    action_type = Column(String(50), nullable=False) # TRIGGER_BACKUP, RESTORE_FILE, LOCK_SNAPSHOT, VERIFY_SNAPSHOT
    resource_id = Column(String(100), nullable=True)
    proposed_payload = Column(Text, nullable=False) # JSON summary of action
    nonce = Column(String(64), unique=True, index=True, nullable=False)
    is_consumed = Column(Boolean, default=False, nullable=False)
    status = Column(String(20), default="PENDING", nullable=False) # PENDING, EXECUTED, EXPIRED, CANCELLED
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    executed_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="ai_actions")


class RansomwareAlert(Base):
    __tablename__ = "ransomware_alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    plan_id = Column(String(36), ForeignKey("backup_plans.id"), nullable=True)
    risk_score = Column(Integer, nullable=False) # 0 to 100
    alert_level = Column(String(20), nullable=False) # SUSPICIOUS, HIGH_RISK, QUARANTINED
    suspicious_files_count = Column(Integer, default=0, nullable=False)
    average_entropy = Column(Float, default=0.0, nullable=False)
    matched_extensions = Column(Text, default="[]", nullable=False) # JSON array of extensions
    details = Column(Text, default="{}", nullable=False) # JSON
    status = Column(String(20), default="ACTIVE", nullable=False) # ACTIVE, DISMISSED, RESOLVED
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    user = relationship("User", back_populates="ransomware_alerts")
    plan = relationship("BackupPlan", back_populates="ransomware_alerts")


class DRDrill(Base):
    __tablename__ = "dr_drills"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    snapshot_id = Column(String(36), ForeignKey("snapshots.id"), nullable=False, index=True)
    files_tested = Column(Integer, nullable=False)
    bytes_tested = Column(BigInteger, nullable=False)
    duration_seconds = Column(Float, nullable=False)
    restoration_speed_mbps = Column(Float, default=0.0, nullable=False)
    rpo_hours = Column(Float, default=0.0, nullable=False)
    estimated_rto_minutes = Column(Float, default=0.0, nullable=False)
    status = Column(String(20), nullable=False) # PASSED, FAILED
    error_details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    user = relationship("User", back_populates="dr_drills")
    snapshot = relationship("Snapshot", back_populates="dr_drills")


class MFARecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    code_hash = Column(String(255), nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="recovery_codes")
