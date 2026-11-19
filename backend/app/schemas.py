from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

# User Schemas
class UserRegister(BaseModel):
    email: str
    password: str = Field(..., min_length=6)
    full_name: str

class UserLogin(BaseModel):
    email: str
    password: str
    mfa_code: Optional[str] = None

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    quota_bytes: int
    used_bytes: int
    is_active: bool
    mfa_enabled: bool = False
    current_key_version: Optional[int] = 1
    created_at: datetime

    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    mfa_required: bool = False
    user: Optional[UserResponse] = None

# Device Schemas
class DeviceRegister(BaseModel):
    device_name: str
    machine_guid: str
    os_type: str = "Windows"
    os_version: str = ""
    agent_version: str = "1.0.0"

class DeviceResponse(BaseModel):
    id: str
    device_name: str
    machine_guid: str
    os_type: str
    os_version: str
    last_seen_at: Optional[datetime]
    is_active: bool

    class Config:
        from_attributes = True

# Backup Schemas
class BackupPlanCreate(BaseModel):
    plan_name: str
    source_directories: List[str]
    exclusion_patterns: Optional[List[str]] = ["*.tmp", ".git", "node_modules", "__pycache__"]
    schedule_type: str = "manual"  # manual, interval, daily
    schedule_expression: str = "3600" # seconds or HH:MM
    retention_days: int = 30
    compression_algo: str = "gzip"

class BackupPlanResponse(BaseModel):
    id: str
    plan_name: str
    source_directories: str
    exclusion_patterns: str
    schedule_type: str
    schedule_expression: str
    retention_days: int
    compression_algo: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class CheckHashRequest(BaseModel):
    sha256_hash: str
    file_size: int

class CheckHashResponse(BaseModel):
    exists: bool
    storage_object_id: Optional[str] = None
    upload_url: Optional[str] = None

class FileItemManifest(BaseModel):
    relative_path: str
    file_name: str
    file_extension: str
    file_size: int
    sha256_hash: str
    modified_at: str
    file_permissions: Optional[str] = "644"

class CommitSnapshotRequest(BaseModel):
    plan_id: str
    snapshot_name: Optional[str] = None
    trigger_type: str = "MANUAL"
    files: List[FileItemManifest]

class SnapshotResponse(BaseModel):
    id: str
    plan_id: str
    snapshot_number: int
    name: str
    snapshot_type: str
    total_files: int
    total_uncompressed_bytes: int
    total_stored_bytes: int
    is_locked: Optional[bool] = False
    is_immutable: Optional[bool] = False
    lock_until: Optional[datetime] = None
    retention_mode: Optional[str] = "SIMULATED"
    provider_lock_type: Optional[str] = "MOCK_SIMULATED"
    retention_period_days: Optional[int] = 0
    verification_status: Optional[str] = "UNVERIFIED"
    created_at: datetime

    class Config:
        from_attributes = True

class SnapshotFileResponse(BaseModel):
    id: str
    relative_path: str
    file_name: str
    file_extension: str
    file_size: int
    modified_at: datetime
    sha256_hash: str
    is_deleted: bool

class BackupJobResponse(BaseModel):
    id: str
    plan_id: Optional[str]
    status: str
    trigger_type: str
    started_at: datetime
    completed_at: Optional[datetime]
    files_scanned: int
    files_uploaded: int
    files_deduplicated: int
    bytes_scanned: int
    bytes_uploaded: int
    bytes_deduplicated: int
    duration_seconds: int
    error_message: Optional[str]

    class Config:
        from_attributes = True

# Recovery / Restore Schemas
class RestoreFileRequest(BaseModel):
    snapshot_file_id: str
    destination_directory: str
    conflict_strategy: str = "overwrite" # overwrite, rename, skip

class RestoreSnapshotRequest(BaseModel):
    snapshot_id: str
    destination_directory: str
    conflict_strategy: str = "overwrite"

class RestoreResponse(BaseModel):
    status: str
    message: str
    files_restored: int
    bytes_restored: int
    destination: str
    integrity_verified: bool

class DeletedFileItem(BaseModel):
    relative_path: str
    file_name: str
    file_extension: str
    file_size: int
    last_seen_snapshot_id: str
    last_seen_snapshot_name: str
    last_seen_date: datetime
    sha256_hash: str
    storage_object_id: str

# Stats Schema
class StorageStatsResponse(BaseModel):
    total_snapshots: int
    total_files_protected: int
    total_uncompressed_bytes: int
    total_stored_bytes: int
    bytes_saved_deduplication: int
    savings_percentage: float
    storage_provider: str
    active_plans: int
    total_backup_jobs: int
