import os
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from backend.app.models import Snapshot, SnapshotFile, StorageObject, BackupPlan
from backend.app.storage.base import StorageProvider
from backend.app.services.backup_service import decompress_payload, calculate_bytes_sha256

def resolve_conflict_path(dest_file: Path, strategy: str) -> Path:
    """Resolve file conflicts according to selected strategy."""
    if not dest_file.exists():
        return dest_file

    if strategy == "overwrite":
        return dest_file
    elif strategy == "rename":
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        stem = dest_file.stem
        suffix = dest_file.suffix
        new_name = f"{stem}_restored_{timestamp}{suffix}"
        return dest_file.parent / new_name
    elif strategy == "skip":
        return None
    return dest_file

def restore_single_snapshot_file(
    snapshot_file: SnapshotFile,
    destination_dir: str,
    conflict_strategy: str,
    storage: StorageProvider
) -> Dict[str, Any]:
    """
    Restore one SnapshotFile:
    1. Fetch storage object.
    2. Download & decompress payload.
    3. Verify SHA-256 checksum.
    4. Write to disk with conflict resolution.
    """
    storage_obj = snapshot_file.storage_object
    if not storage_obj:
        raise ValueError(f"StorageObject missing for file: {snapshot_file.relative_path}")

    # 1. Download from storage provider
    compressed_bytes = storage.download_bytes(storage_obj.storage_path)

    # 2. Decompress
    try:
        restored_bytes = decompress_payload(compressed_bytes, storage_obj.compression_algo)
    except Exception as e:
        raise ValueError(f"Integrity check failed: storage payload is corrupted ({e})")

    # 3. Checksum Verification
    computed_hash = calculate_bytes_sha256(restored_bytes)
    if computed_hash != storage_obj.sha256_hash:
        raise ValueError(
            f"Integrity check failed for {snapshot_file.file_name}! "
            f"Expected SHA-256: {storage_obj.sha256_hash}, got: {computed_hash}"
        )

    # 4. Write to destination
    dest_base = Path(destination_dir).resolve()
    target_path = dest_base / snapshot_file.relative_path

    resolved_path = resolve_conflict_path(target_path, conflict_strategy)
    if resolved_path is None:
        return {
            "file_name": snapshot_file.file_name,
            "status": "SKIPPED",
            "bytes_restored": 0,
            "path": str(target_path)
        }

    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    with open(resolved_path, "wb") as f:
        f.write(restored_bytes)

    return {
        "file_name": snapshot_file.file_name,
        "status": "RESTORED",
        "bytes_restored": len(restored_bytes),
        "path": str(resolved_path),
        "sha256_verified": True
    }

def restore_file_by_id(
    snapshot_file_id: str,
    destination_dir: str,
    conflict_strategy: str,
    db: Session,
    storage: StorageProvider,
    user_id: str = None
) -> Dict[str, Any]:
    """Restore a specific file from a snapshot by its SnapshotFile ID with user ownership check."""
    snap_file = db.query(SnapshotFile).filter(SnapshotFile.id == snapshot_file_id).first()
    if not snap_file:
        raise ValueError(f"SnapshotFile not found: {snapshot_file_id}")

    if user_id and snap_file.snapshot and snap_file.snapshot.user_id != user_id:
        raise PermissionError("Access denied: You do not own this snapshot file")

    return restore_single_snapshot_file(snap_file, destination_dir, conflict_strategy, storage)

def restore_snapshot(
    snapshot_id: str,
    destination_dir: str,
    conflict_strategy: str,
    db: Session,
    storage: StorageProvider,
    user_id: str = None
) -> Dict[str, Any]:
    """Restore all files from a point-in-time snapshot with user ownership check."""
    snapshot = db.query(Snapshot).filter(Snapshot.id == snapshot_id).first()
    if not snapshot:
        raise ValueError(f"Snapshot not found: {snapshot_id}")

    if user_id and snapshot.user_id != user_id:
        raise PermissionError("Access denied: You do not own this snapshot")

    files_restored = 0
    bytes_restored = 0
    results = []

    for s_file in snapshot.files:
        if s_file.is_deleted:
            continue
        res = restore_single_snapshot_file(s_file, destination_dir, conflict_strategy, storage)
        results.append(res)
        if res["status"] == "RESTORED":
            files_restored += 1
            bytes_restored += res["bytes_restored"]

    return {
        "snapshot_id": snapshot.id,
        "snapshot_name": snapshot.name,
        "files_restored": files_restored,
        "bytes_restored": bytes_restored,
        "destination": str(Path(destination_dir).resolve()),
        "integrity_verified": True,
        "details": results
    }

def get_deleted_files_for_plan(plan_id: str, db: Session, user_id: str = None) -> List[Dict[str, Any]]:
    """
    Find files that exist in historical snapshots but are absent in the latest snapshot.
    Enables one-click Deleted-File Recovery (Soft-Delete / Trash).
    """
    query = db.query(Snapshot).filter(Snapshot.plan_id == plan_id)
    if user_id:
        query = query.filter(Snapshot.user_id == user_id)
    snapshots = query.order_by(Snapshot.snapshot_number.asc()).all()

    if not snapshots:
        return []

    latest_snapshot = snapshots[-1]
    latest_file_paths = {f.relative_path for f in latest_snapshot.files if not f.is_deleted}

    deleted_candidates: Dict[str, Dict[str, Any]] = {}

    # Inspect all historical snapshots in order
    for snap in snapshots:
        for f in snap.files:
            if not f.is_deleted:
                # If this file path is missing in latest snapshot, it was deleted!
                if f.relative_path not in latest_file_paths:
                    deleted_candidates[f.relative_path] = {
                        "snapshot_file_id": f.id,
                        "relative_path": f.relative_path,
                        "file_name": f.file_name,
                        "file_extension": f.file_extension,
                        "file_size": f.file_size,
                        "last_seen_snapshot_id": snap.id,
                        "last_seen_snapshot_name": snap.name,
                        "last_seen_date": snap.created_at,
                        "sha256_hash": f.storage_object.sha256_hash if f.storage_object else "",
                        "storage_object_id": f.storage_object_id
                    }

    return list(deleted_candidates.values())
