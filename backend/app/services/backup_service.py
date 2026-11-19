import os
import gzip
import hashlib
import fnmatch
import secrets
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from backend.app.config import settings
from backend.app.models import User, BackupPlan, BackupJob, StorageObject, Snapshot, SnapshotFile
from backend.app.storage.base import StorageProvider
from backend.app.services.crypto_service import envelope_encrypt_payload

def calculate_sha256(file_path: str) -> str:
    """Calculate SHA-256 checksum of a file streaming in 64 KB chunks."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def calculate_bytes_sha256(data: bytes) -> str:
    """Calculate SHA-256 of bytes in memory."""
    return hashlib.sha256(data).hexdigest()

def is_excluded(rel_path: str, exclusions: List[str]) -> bool:
    """Check if relative path matches any exclusion glob patterns."""
    path_str = rel_path.replace("\\", "/")
    parts = path_str.split("/")
    for pattern in exclusions:
        if fnmatch.fnmatch(path_str, pattern):
            return True
        for part in parts:
            if fnmatch.fnmatch(part, pattern):
                return True
    return False

def scan_directory(dir_path: str, exclusions: List[str] = None) -> List[Dict[str, Any]]:
    """Recursively scan a directory, returning metadata of all non-excluded files."""
    exclusions = exclusions or ["*.tmp", ".git", "node_modules", "__pycache__", ".venv"]
    base = Path(dir_path).resolve()
    if not base.exists() or not base.is_dir():
        return []

    results = []
    for root, dirs, files in os.walk(base):
        # Exclude directories in-place for performance
        dirs[:] = [d for d in dirs if not is_excluded(d, exclusions)]

        for file in files:
            full_path = Path(root) / file
            try:
                rel_path = str(full_path.relative_to(base)).replace("\\", "/")
            except ValueError:
                rel_path = file

            if is_excluded(rel_path, exclusions):
                continue

            try:
                stat = full_path.stat()
                results.append({
                    "full_path": str(full_path),
                    "relative_path": rel_path,
                    "file_name": file,
                    "file_extension": full_path.suffix.lower(),
                    "file_size": stat.st_size,
                    "modified_at": datetime.utcfromtimestamp(stat.st_mtime)
                })
            except (OSError, PermissionError):
                continue
    return results

def compress_payload(data: bytes, algo: str = "gzip") -> bytes:
    """Compress payload using specified algorithm."""
    if algo == "gzip":
        return gzip.compress(data, compresslevel=6)
    return data

def decompress_payload(data: bytes, algo: str = "gzip") -> bytes:
    """Decompress payload."""
    if algo == "gzip":
        return gzip.decompress(data)
    return data

def backup_single_file(
    file_info: Dict[str, Any],
    plan: BackupPlan,
    user: User,
    db: Session,
    storage: StorageProvider
) -> Tuple[StorageObject, bool]:
    """
    Process one file:
    1. Calculate SHA-256 hash.
    2. Check if StorageObject already exists (Deduplication).
    3. If exists, increment ref_count, skip upload (0 bytes uploaded).
    4. If new, compress payload and upload to storage provider.
    Returns (StorageObject, was_uploaded: bool).
    """
    full_path = file_info["full_path"]
    sha256 = calculate_sha256(full_path)
    original_size = file_info["file_size"]

    # Check for existing deduplicated object
    existing_obj = db.query(StorageObject).filter(
        StorageObject.user_id == user.id,
        StorageObject.sha256_hash == sha256
    ).first()

    if existing_obj:
        # DEDUPLICATION HIT: Increment reference count
        existing_obj.ref_count += 1
        return existing_obj, False

    # DEDUPLICATION MISS: Read, Compress, and Upload
    with open(full_path, "rb") as f:
        raw_data = f.read()

    compressed_data = compress_payload(raw_data, plan.compression_algo)
    compressed_size = len(compressed_data)

    # Envelope Encryption (Zero-Trust AES-256-GCM)
    is_enc_enabled = getattr(plan, "encryption_enabled", True)
    if is_enc_enabled:
        if not user.encryption_salt:
            user.encryption_salt = secrets.token_hex(16)
            db.flush()
        key_ver = getattr(user, "current_key_version", 1) or 1
        aad_ctx = f"{user.id}:{sha256}:{key_ver}"
        enc_res = envelope_encrypt_payload(
            plaintext=compressed_data,
            user_id=user.id,
            salt=user.encryption_salt,
            key_version=key_ver,
            aad_context=aad_ctx
        )
        payload_to_upload = enc_res["ciphertext"]
        is_encrypted = True
        encryption_nonce = enc_res["payload_nonce"].hex()
        encrypted_dek = enc_res["encrypted_dek"].hex()
        dek_nonce = enc_res["dek_nonce"].hex()
        stored_bytes_count = len(payload_to_upload)
    else:
        payload_to_upload = compressed_data
        is_encrypted = False
        encryption_nonce = None
        encrypted_dek = None
        dek_nonce = None
        key_ver = 1
        aad_ctx = None
        stored_bytes_count = compressed_size

    storage_path = f"objects/{sha256}"
    storage.upload_bytes(payload_to_upload, storage_path)

    new_obj = StorageObject(
        user_id=user.id,
        sha256_hash=sha256,
        original_size=original_size,
        compressed_size=stored_bytes_count,
        compression_algo=plan.compression_algo,
        is_encrypted=is_encrypted,
        encryption_algo="AES-256-GCM" if is_encrypted else "NONE",
        encryption_nonce=encryption_nonce,
        encrypted_dek=encrypted_dek,
        dek_nonce=dek_nonce,
        key_version=key_ver,
        aad_tag=aad_ctx,
        storage_provider=settings.STORAGE_PROVIDER,
        storage_path=storage_path,
        storage_class="STANDARD",
        ref_count=1
    )
    db.add(new_obj)
    db.flush()

    user.used_bytes += stored_bytes_count
    return new_obj, True

def execute_backup_plan(
    plan_id: str,
    user: User,
    db: Session,
    storage: StorageProvider,
    trigger_type: str = "MANUAL",
    custom_name: str = None
) -> Tuple[Snapshot, BackupJob]:
    """Execute a complete backup plan and record snapshot & job execution metrics."""
    plan = db.query(BackupPlan).filter(BackupPlan.id == plan_id).first()
    if not plan:
        raise ValueError(f"Backup plan not found: {plan_id}")

    import json
    try:
        source_dirs = json.loads(plan.source_directories)
    except Exception:
        source_dirs = [plan.source_directories]

    try:
        exclusions = json.loads(plan.exclusion_patterns)
    except Exception:
        exclusions = ["*.tmp", ".git", "node_modules", "__pycache__"]

    start_time = datetime.utcnow()
    job = BackupJob(
        plan_id=plan.id,
        user_id=user.id,
        status="RUNNING",
        trigger_type=trigger_type,
        started_at=start_time
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        files_to_backup = []
        for sdir in source_dirs:
            scanned = scan_directory(sdir, exclusions)
            files_to_backup.extend(scanned)

        # Determine next snapshot sequence number
        last_snap = db.query(Snapshot).filter(
            Snapshot.plan_id == plan.id
        ).order_by(Snapshot.snapshot_number.desc()).first()
        next_num = (last_snap.snapshot_number + 1) if last_snap else 1

        snap_name = custom_name or f"{plan.plan_name} - Snapshot #{next_num} ({start_time.strftime('%Y-%m-%d %H:%M')})"
        snapshot = Snapshot(
            plan_id=plan.id,
            user_id=user.id,
            snapshot_number=next_num,
            name=snap_name,
            snapshot_type="incremental" if next_num > 1 else "full"
        )
        db.add(snapshot)
        db.flush()

        files_scanned = len(files_to_backup)
        files_uploaded = 0
        files_deduped = 0
        bytes_scanned = 0
        bytes_uploaded = 0
        bytes_deduped = 0

        for f_info in files_to_backup:
            bytes_scanned += f_info["file_size"]
            storage_obj, was_uploaded = backup_single_file(f_info, plan, user, db, storage)

            if was_uploaded:
                files_uploaded += 1
                bytes_uploaded += storage_obj.compressed_size
            else:
                files_deduped += 1
                bytes_deduped += storage_obj.original_size

            # Create snapshot file record
            snap_file = SnapshotFile(
                snapshot_id=snapshot.id,
                storage_object_id=storage_obj.id,
                relative_path=f_info["relative_path"],
                file_name=f_info["file_name"],
                file_extension=f_info["file_extension"],
                file_size=f_info["file_size"],
                modified_at=f_info["modified_at"],
                is_deleted=False
            )
            db.add(snap_file)

        # Update snapshot stats
        snapshot.total_files = files_scanned
        snapshot.total_uncompressed_bytes = bytes_scanned
        snapshot.total_stored_bytes = bytes_uploaded

        # Complete Job
        end_time = datetime.utcnow()
        duration = max(1, int((end_time - start_time).total_seconds()))

        job.status = "SUCCESS"
        job.completed_at = end_time
        job.files_scanned = files_scanned
        job.files_uploaded = files_uploaded
        job.files_deduplicated = files_deduped
        job.bytes_scanned = bytes_scanned
        job.bytes_uploaded = bytes_uploaded
        job.bytes_deduplicated = bytes_deduped
        job.duration_seconds = duration

        db.commit()
        db.refresh(snapshot)
        db.refresh(job)
        return snapshot, job

    except Exception as e:
        db.rollback()
        job.status = "FAILED"
        job.completed_at = datetime.utcnow()
        job.error_message = str(e)
        db.commit()
        raise e
