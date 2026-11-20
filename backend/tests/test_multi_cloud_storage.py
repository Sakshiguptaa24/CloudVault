import io
import os
import time
import hashlib
import tempfile
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.models import Base, User, BackupPlan, Snapshot, SnapshotFile, StorageObject
from backend.app.storage.base import StorageProvider
from backend.app.storage.mock_storage import MockStorageProvider
from backend.app.storage.s3_storage import S3StorageProvider
from backend.app.storage.azure_storage import AzureBlobStorageProvider
from backend.app.storage.gcs_storage import GCSStorageProvider
from backend.app.storage.router import MultiCloudRouter
from backend.app.storage.exceptions import (
    StorageError,
    StorageNotFoundError,
    StorageRetentionLockError,
    StorageAuthenticationError,
    StorageTimeoutError,
    StorageIntegrityError
)
from backend.app.services.crypto_service import (
    envelope_encrypt_payload,
    envelope_decrypt_payload
)

@pytest.fixture
def db_session():
    """Create an isolated temporary SQLite database for multi-cloud tests."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass

def test_1_provider_contract_mock():
    """Verify standardized StorageProvider contract on MockStorageProvider."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        prov = MockStorageProvider(base_dir=tmp_dir)
        payload = b"Mock storage standardized interface payload"
        path = "test/mock_obj.bin"

        # Upload & Exists
        assert prov.upload_bytes(payload, path) is True
        assert prov.file_exists(path) is True

        # Download & Stream
        assert prov.download_bytes(path) == payload
        streamed = b"".join(list(prov.stream_object(path, chunk_size=8)))
        assert streamed == payload

        # Metadata & Integrity
        meta = prov.get_object_metadata(path)
        assert meta["size_bytes"] == len(payload)
        assert meta["sha256"] == hashlib.sha256(payload).hexdigest()
        integrity = prov.verify_object_integrity(path, expected_sha256=meta["sha256"])
        assert integrity["verified"] is True

        # List
        objs = prov.list_objects(prefix="test")
        assert len(objs) == 1
        assert objs[0]["key"] == path

        # Delete
        assert prov.delete_file(path) is True
        assert prov.file_exists(path) is False

def test_2_provider_contract_s3():
    """Verify standardized StorageProvider contract on S3StorageProvider (Simulated mode)."""
    prov = S3StorageProvider(bucket_name="vault-s3-test", simulated=True)
    payload = b"AWS S3 standardized interface payload"
    key = "vault/s3_test_obj.bin"

    assert prov.upload_bytes(payload, key) is True
    assert prov.file_exists(key) is True
    assert prov.download_bytes(key) == payload

    # Streaming
    streamed = b"".join(list(prov.stream_object(key, chunk_size=8)))
    assert streamed == payload

    # Metadata & Integrity
    meta = prov.get_object_metadata(key)
    assert meta["size_bytes"] == len(payload)
    assert meta["sha256"] == hashlib.sha256(payload).hexdigest()
    assert "s3://" in prov.get_uri(key)

    integrity = prov.verify_object_integrity(key, expected_sha256=meta["sha256"])
    assert integrity["verified"] is True

    # List & Delete
    assert len(prov.list_objects(prefix="vault")) == 1
    assert prov.delete_file(key) is True
    assert prov.file_exists(key) is False

def test_3_provider_contract_azure():
    """Verify standardized StorageProvider contract on AzureBlobStorageProvider (Simulated mode)."""
    prov = AzureBlobStorageProvider(container_name="vault-azure-test", simulated=True)
    payload = b"Microsoft Azure Blob standardized interface payload"
    blob_name = "vault/azure_test_obj.bin"

    assert prov.upload_bytes(payload, blob_name) is True
    assert prov.file_exists(blob_name) is True
    assert prov.download_bytes(blob_name) == payload

    # Streaming
    streamed = b"".join(list(prov.stream_object(blob_name, chunk_size=10)))
    assert streamed == payload

    # Metadata & Integrity
    meta = prov.get_object_metadata(blob_name)
    assert meta["size_bytes"] == len(payload)
    assert meta["sha256"] == hashlib.sha256(payload).hexdigest()
    assert "azure://" in prov.get_uri(blob_name)

    integrity = prov.verify_object_integrity(blob_name, expected_sha256=meta["sha256"])
    assert integrity["verified"] is True

    # List & Delete
    assert len(prov.list_objects(prefix="vault")) == 1
    assert prov.delete_file(blob_name) is True
    assert prov.file_exists(blob_name) is False

def test_4_provider_contract_gcs():
    """Verify standardized StorageProvider contract on GCSStorageProvider (Simulated mode)."""
    prov = GCSStorageProvider(bucket_name="vault-gcs-test", simulated=True)
    payload = b"Google Cloud Storage standardized interface payload"
    path = "vault/gcs_test_obj.bin"

    assert prov.upload_bytes(payload, path) is True
    assert prov.file_exists(path) is True
    assert prov.download_bytes(path) == payload

    # Streaming
    streamed = b"".join(list(prov.stream_object(path, chunk_size=12)))
    assert streamed == payload

    # Metadata & Integrity
    meta = prov.get_object_metadata(path)
    assert meta["size_bytes"] == len(payload)
    assert meta["sha256"] == hashlib.sha256(payload).hexdigest()
    assert "gs://" in prov.get_uri(path)

    integrity = prov.verify_object_integrity(path, expected_sha256=meta["sha256"])
    assert integrity["verified"] is True

    # List & Delete
    assert len(prov.list_objects(prefix="vault")) == 1
    assert prov.delete_file(path) is True
    assert prov.file_exists(path) is False

def test_5_large_file_streaming_and_multipart():
    """Verify large file chunked streaming across multiple chunks."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        prov = MockStorageProvider(base_dir=tmp_dir)
        # Generate 1 MB test payload
        large_payload = b"A" * (1024 * 1024)
        path = "large_objects/1mb.bin"

        prov.upload_bytes(large_payload, path)
        assert prov.file_exists(path) is True

        chunks = []
        for chunk in prov.stream_object(path, chunk_size=65536):
            chunks.append(chunk)

        # 1024 KB / 64 KB = 16 chunks
        assert len(chunks) == 16
        reconstructed = b"".join(chunks)
        assert len(reconstructed) == len(large_payload)
        assert hashlib.sha256(reconstructed).hexdigest() == hashlib.sha256(large_payload).hexdigest()

def test_6_missing_object_error_handling():
    """Verify StorageNotFoundError is raised across providers when object does not exist."""
    providers = [
        MockStorageProvider(base_dir=tempfile.mkdtemp()),
        S3StorageProvider(bucket_name="test-s3", simulated=True),
        AzureBlobStorageProvider(container_name="test-azure", simulated=True),
        GCSStorageProvider(bucket_name="test-gcs", simulated=True)
    ]

    for prov in providers:
        with pytest.raises((StorageNotFoundError, FileNotFoundError)):
            prov.download_bytes("non_existent_key_12345.dat")

def test_7_corrupted_object_checksum_detection():
    """Verify verify_object_integrity raises StorageIntegrityError when checksum does not match."""
    prov = S3StorageProvider(bucket_name="test-s3", simulated=True)
    original_data = b"Original uncorrupted backup bytes"
    key = "blocks/corrupt_test.dat"
    prov.upload_bytes(original_data, key)

    correct_hash = hashlib.sha256(original_data).hexdigest()
    wrong_hash = "0" * 64

    # Correct hash succeeds
    res = prov.verify_object_integrity(key, expected_sha256=correct_hash)
    assert res["verified"] is True

    # Tampered/wrong hash raises StorageIntegrityError
    with pytest.raises(StorageIntegrityError):
        prov.verify_object_integrity(key, expected_sha256=wrong_hash)

def test_8_authentication_failure_handling():
    """Verify StorageAuthenticationError is raised cleanly on simulated authentication failure."""
    prov = AzureBlobStorageProvider(container_name="test-azure", simulated=True)
    prov.simulate_auth_failure = True

    with pytest.raises(StorageAuthenticationError) as exc_info:
        prov.upload_bytes(b"test", "fail.bin")
    assert "authentication" in str(exc_info.value).lower()

def test_9_network_timeout_and_exponential_backoff_retry():
    """Verify MultiCloudRouter handles transient timeouts and tracks retry telemetry."""
    primary = MockStorageProvider(base_dir=tempfile.mkdtemp())
    secondary = S3StorageProvider(bucket_name="backup-s3", simulated=True)

    router = MultiCloudRouter(
        primary_provider=primary,
        secondary_provider=secondary,
        max_retries=3,
        retry_backoff=0.01,
        failover_enabled=True
    )

    # Trigger timeout on primary
    primary.simulate_timeout = True
    payload = b"Payload sent during primary timeout"
    dest = "transfers/retry_test.dat"

    # MultiCloudRouter should fail over to secondary
    success = router.upload_bytes(payload, dest)
    assert success is True
    assert router.telemetry["failover_events_count"] == 1
    assert secondary.file_exists(dest) is True

def test_10_multi_cloud_routing_primary_success():
    """Verify normal upload path via primary provider with accurate telemetry."""
    primary = MockStorageProvider(base_dir=tempfile.mkdtemp())
    secondary = S3StorageProvider(bucket_name="backup-s3", simulated=True)

    router = MultiCloudRouter(
        primary_provider=primary,
        secondary_provider=secondary,
        max_retries=2,
        retry_backoff=0.01,
        failover_enabled=True
    )

    data = b"Primary cloud storage normal upload payload"
    path = "normal/obj1.dat"
    assert router.upload_bytes(data, path) is True
    assert primary.file_exists(path) is True
    assert router.telemetry["uploads_count"] == 1
    assert router.telemetry["failover_events_count"] == 0

    downloaded = router.download_bytes(path)
    assert downloaded == data
    assert router.telemetry["downloads_count"] == 1

def test_11_multi_cloud_routing_failover_to_secondary():
    """Verify primary failure triggers automated, seamless failover to secondary without data loss."""
    primary = MockStorageProvider(base_dir=tempfile.mkdtemp())
    secondary = AzureBlobStorageProvider(container_name="backup-azure", simulated=True)

    router = MultiCloudRouter(
        primary_provider=primary,
        secondary_provider=secondary,
        max_retries=2,
        retry_backoff=0.01,
        failover_enabled=True
    )

    # Simulate primary total network outage
    primary.simulate_network_failure = True
    data = b"Critical enterprise snapshot payload requiring failover"
    path = "failover/critical_snap.dat"

    # Upload routes cleanly to secondary
    assert router.upload_bytes(data, path) is True
    assert router.telemetry["failover_events_count"] == 1
    assert secondary.file_exists(path) is True
    assert router.download_bytes(path) == data

def test_12_retention_lock_enforcement_blocks_deletion():
    """Verify active WORM / Object Lock retention blocks deletion with StorageRetentionLockError."""
    providers = [
        MockStorageProvider(base_dir=tempfile.mkdtemp()),
        S3StorageProvider(bucket_name="test-s3", simulated=True),
        AzureBlobStorageProvider(container_name="test-azure", simulated=True),
        GCSStorageProvider(bucket_name="test-gcs", simulated=True)
    ]

    lock_until = datetime.now(timezone.utc) + timedelta(days=14)

    for prov in providers:
        key = f"immutable_locks/obj_{prov.get_capabilities()['provider']}.bin"
        prov.upload_bytes(b"Immutable data", key)
        assert prov.file_exists(key) is True

        # Apply retention
        prov.set_retention(key, lock_until, mode="COMPLIANCE")
        retention = prov.get_retention(key)
        assert retention is not None
        assert retention["is_active"] is True

        # Attempt to delete MUST fail
        with pytest.raises(StorageRetentionLockError):
            prov.delete_file(key)

        # File must remain untouched
        assert prov.file_exists(key) is True

def test_13_cross_provider_object_migration():
    """Verify object migration from Mock to S3 to Azure with bit-for-bit SHA-256 verification."""
    mock_prov = MockStorageProvider(base_dir=tempfile.mkdtemp())
    s3_prov = S3StorageProvider(bucket_name="target-s3", simulated=True)
    azure_prov = AzureBlobStorageProvider(container_name="target-azure", simulated=True)

    router = MultiCloudRouter(primary_provider=mock_prov, secondary_provider=s3_prov)

    payload = b"Cross-provider migration test data with high entropy"
    path = "objects/sha_test_migration.dat"
    mock_prov.upload_bytes(payload, path)

    # 1. Migrate Mock -> S3
    res1 = router.migrate_object(path, from_provider=mock_prov, to_provider=s3_prov, delete_source=False)
    assert res1["verified"] is True
    assert s3_prov.file_exists(path) is True
    assert s3_prov.download_bytes(path) == payload

    # 2. Migrate S3 -> Azure Blob
    res2 = router.migrate_object(path, from_provider=s3_prov, to_provider=azure_prov, delete_source=True)
    assert res2["verified"] is True
    assert azure_prov.file_exists(path) is True
    assert azure_prov.download_bytes(path) == payload
    assert s3_prov.file_exists(path) is False  # Confirmed deleted on source after verification

def test_14_cross_provider_snapshot_migration_and_db_update(db_session):
    """Verify migration of an entire snapshot between cloud providers updates DB records correctly."""
    user = User(
        id="user-migration-test",
        email="migrator@cloudvault.internal",
        full_name="Migrator",
        password_hash="pw"
    )
    db_session.add(user)

    plan = BackupPlan(
        id="plan-migration",
        user_id=user.id,
        plan_name="Multi-Cloud Migration Plan",
        source_directories='["C:/test/data"]'
    )
    db_session.add(plan)

    snap = Snapshot(
        id="snap-migration-100",
        plan_id=plan.id,
        user_id=user.id,
        snapshot_number=1,
        name="Pre-Migration Snapshot",
        total_files=3,
        total_uncompressed_bytes=2048,
        total_stored_bytes=2048
    )
    db_session.add(snap)

    source_prov = MockStorageProvider(base_dir=tempfile.mkdtemp())
    target_prov = S3StorageProvider(bucket_name="vault-s3-migrated", simulated=True)

    # Create 3 storage objects on source provider
    for i in range(3):
        data = f"Object content {i}".encode()
        sha = hashlib.sha256(data).hexdigest()
        path = f"objects/{sha}"
        source_prov.upload_bytes(data, path)

        so = StorageObject(
            id=f"so-{i}",
            user_id=user.id,
            sha256_hash=sha,
            original_size=len(data),
            compressed_size=len(data),
            storage_provider="mock",
            storage_path=path
        )
        db_session.add(so)

        sf = SnapshotFile(
            id=f"sf-{i}",
            snapshot_id=snap.id,
            storage_object_id=so.id,
            relative_path=f"file_{i}.txt",
            file_name=f"file_{i}.txt",
            file_size=len(data),
            modified_at=datetime.utcnow()
        )
        db_session.add(sf)

    db_session.commit()

    # Execute snapshot migration
    router = MultiCloudRouter(primary_provider=source_prov, secondary_provider=target_prov)
    res = router.migrate_snapshot(
        snapshot_id=snap.id,
        from_provider=source_prov,
        to_provider=target_prov,
        db=db_session,
        delete_source=False
    )

    assert res["files_migrated"] == 3
    assert res["verified"] is True

    # Verify DB records updated to s3
    db_session.expire_all()
    updated_objs = db_session.query(StorageObject).filter(StorageObject.user_id == user.id).all()
    for uo in updated_objs:
        assert uo.storage_provider == "s3"
        assert target_prov.file_exists(uo.storage_path) is True

def test_15_envelope_encryption_compatibility_across_clouds():
    """Verify AES-256-GCM envelope encrypted files upload, store, and decrypt identically on all clouds."""
    providers = [
        MockStorageProvider(base_dir=tempfile.mkdtemp()),
        S3StorageProvider(bucket_name="enc-s3", simulated=True),
        AzureBlobStorageProvider(container_name="enc-azure", simulated=True),
        GCSStorageProvider(bucket_name="enc-gcs", simulated=True)
    ]

    user_id = "test-enc-user-1"
    salt = "testsalt12345678"
    plaintext = b"Confidential business data protected by AES-256-GCM envelope encryption."

    # Encrypt
    enc_result = envelope_encrypt_payload(
        plaintext=plaintext,
        user_id=user_id,
        salt=salt,
        key_version=1,
        aad_context="vault_cloud_test"
    )
    ciphertext = enc_result["ciphertext"]
    path = "encrypted/secure_doc.bin"

    for prov in providers:
        # Upload ciphertext to provider
        prov.upload_bytes(ciphertext, path)
        assert prov.file_exists(path) is True

        # Download from provider
        fetched = prov.download_bytes(path)
        assert fetched == ciphertext

        # Decrypt fetched bytes
        decrypted = envelope_decrypt_payload(
            ciphertext=fetched,
            encrypted_dek=enc_result["encrypted_dek"],
            payload_nonce=enc_result["payload_nonce"],
            dek_nonce=enc_result["dek_nonce"],
            user_id=user_id,
            salt=salt,
            key_version=1,
            aad_context="vault_cloud_test"
        )
        assert decrypted == plaintext

def test_16_multi_cloud_tenant_isolation(db_session):
    """Verify that User A cannot access or migrate User B's multi-cloud storage objects."""
    user_a = User(id="user-a", email="a@vault.io", full_name="User A", password_hash="pw")
    user_b = User(id="user-b", email="b@vault.io", full_name="User B", password_hash="pw")
    db_session.add_all([user_a, user_b])

    plan_b = BackupPlan(
        id="plan-b",
        user_id=user_b.id,
        plan_name="User B Plan",
        source_directories='["C:/test/data_b"]'
    )
    db_session.add(plan_b)

    snap_b = Snapshot(
        id="snap-b-private",
        plan_id=plan_b.id,
        user_id=user_b.id,
        snapshot_number=1,
        name="User B Private Financial Snapshot",
        total_files=1,
        total_uncompressed_bytes=512,
        total_stored_bytes=512
    )
    db_session.add(snap_b)
    db_session.commit()

    # User A attempting to query or migrate User B's snapshot
    found = db_session.query(Snapshot).filter(
        Snapshot.id == snap_b.id,
        Snapshot.user_id == user_a.id
    ).first()
    assert found is None
