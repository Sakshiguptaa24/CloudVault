import os
os.environ["TESTING"] = "1"
import shutil
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.storage.mock_storage import MockStorageProvider
from backend.app.storage import _storage_instance

# Test Database setup
TEST_DB_PATH = Path("./data/test_cloudvault.db").resolve()
TEST_MOCK_STORAGE = Path("./data/test_mock_storage").resolve()

TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
TEST_MOCK_STORAGE.mkdir(parents=True, exist_ok=True)

test_engine = create_engine(
    f"sqlite:///{TEST_DB_PATH}",
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    import backend.app.storage as storage_mod
    mock_prov = MockStorageProvider(base_dir=str(TEST_MOCK_STORAGE))
    storage_mod._storage_instance = mock_prov

    yield

    # Teardown
    if TEST_DB_PATH.exists():
        try:
            TEST_DB_PATH.unlink()
        except Exception:
            pass
    if TEST_MOCK_STORAGE.exists():
        try:
            shutil.rmtree(TEST_MOCK_STORAGE, ignore_errors=True)
        except Exception:
            pass

@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
