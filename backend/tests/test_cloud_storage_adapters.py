import pytest
import os
import tempfile
from pathlib import Path
from backend.app.storage.mock_storage import MockStorageProvider
from backend.app.storage.s3_storage import S3StorageProvider
from backend.app.storage.azure_storage import AzureBlobStorageProvider
from backend.app.storage import get_multi_cloud_inventory
from backend.app.main import multi_cloud_status, health_check

def test_mock_storage_provider_lifecycle():
    with tempfile.TemporaryDirectory() as tmp_dir:
        prov = MockStorageProvider(base_dir=tmp_dir)
        
        # Test Capabilities
        caps = prov.get_capabilities()
        assert caps["provider"] == "mock"
        assert caps["features"]["streaming_upload"] is True
        assert caps["features"]["worm_retention"] is True

        # Test Health Check
        health = prov.health_check()
        assert health["status"] == "HEALTHY"
        assert health["writable"] is True
        assert health["latency_ms"] >= 0

        # Upload and Download Bytes
        data = b"Multi-cloud storage test payload."
        path = "test_dir/file.bin"
        assert prov.upload_bytes(data, path) is True
        assert prov.file_exists(path) is True

        downloaded = prov.download_bytes(path)
        assert downloaded == data

        # Test Object Metadata
        meta = prov.get_object_metadata(path)
        assert meta["size_bytes"] == len(data)
        assert "sha256" in meta

        # Delete
        assert prov.delete_file(path) is True
        assert prov.file_exists(path) is False

def test_s3_storage_provider_lifecycle():
    s3_prov = S3StorageProvider(bucket_name="cloudvault-test-s3", simulated=True)
    
    # Test Capabilities
    caps = s3_prov.get_capabilities()
    assert caps["provider"] == "s3"
    assert "GLACIER" in caps["features"]["tiering"]
    assert caps["features"]["worm_retention"] is True

    # Test Health Check
    health = s3_prov.health_check()
    assert health["status"] == "HEALTHY"
    assert health["writable"] is True

    # Test Upload/Download
    payload = b"Amazon S3 encrypted archive block"
    key = "vault/blocks/s3_block_01.dat"
    assert s3_prov.upload_bytes(payload, key) is True
    assert s3_prov.file_exists(key) is True

    fetched = s3_prov.download_bytes(key)
    assert fetched == payload

    meta = s3_prov.get_object_metadata(key)
    assert meta["size_bytes"] == len(payload)

    assert s3_prov.delete_file(key) is True
    assert s3_prov.file_exists(key) is False

def test_azure_blob_storage_provider_lifecycle():
    azure_prov = AzureBlobStorageProvider(container_name="cloudvault-test-azure", simulated=True)
    
    # Test Capabilities
    caps = azure_prov.get_capabilities()
    assert caps["provider"] == "azure"
    assert "HOT" in caps["features"]["tiering"]
    assert "ARCHIVE" in caps["features"]["tiering"]
    assert caps["features"]["worm_retention"] is True

    # Test Health Check
    health = azure_prov.health_check()
    assert health["status"] == "HEALTHY"
    assert health["writable"] is True

    # Test Upload/Download
    payload = b"Microsoft Azure immutable blob container block"
    blob_name = "vault/blocks/azure_block_01.dat"
    assert azure_prov.upload_bytes(payload, blob_name) is True
    assert azure_prov.file_exists(blob_name) is True

    retrieved = azure_prov.download_bytes(blob_name)
    assert retrieved == payload

    meta = azure_prov.get_object_metadata(blob_name)
    assert meta["size_bytes"] == len(payload)

    assert azure_prov.delete_file(blob_name) is True
    assert azure_prov.file_exists(blob_name) is False

def test_multi_cloud_inventory_and_endpoints():
    inventory = get_multi_cloud_inventory()
    assert "active_provider" in inventory
    assert "supported_clouds" in inventory
    assert "gcs" in inventory["supported_clouds"]
    assert "aws_s3" in inventory["supported_clouds"]
    assert "azure_blob" in inventory["supported_clouds"]

    status_data = multi_cloud_status()
    assert "supported_clouds" in status_data

    health_data = health_check()
    assert health_data["version"] == "2.0.0"
    assert "storage_health" in health_data
    assert "capabilities" in health_data
