import pytest
from backend.app.storage.mock_storage import MockStorageProvider

def test_mock_storage_operations(tmp_path):
    storage = MockStorageProvider(base_dir=str(tmp_path / "mock_store"))

    # Test upload and download bytes
    data = b"Hello, CloudVault mock cloud storage!"
    dest = "objects/test_hash_123"

    assert storage.upload_bytes(data, dest) is True
    assert storage.file_exists(dest) is True

    downloaded = storage.download_bytes(dest)
    assert downloaded == data

    # Test download to file
    local_dest = tmp_path / "downloaded_file.txt"
    assert storage.download_file(dest, str(local_dest)) is True
    assert local_dest.read_bytes() == data

    # Test delete
    assert storage.delete_file(dest) is True
    assert storage.file_exists(dest) is False

