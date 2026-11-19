import os
from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    # Security
    SECRET_KEY: str = "cloudvault-super-secret-key-change-in-production-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    ALLOWED_ORIGINS: str = "*"
    MAX_UPLOAD_SIZE_BYTES: int = 104857600  # 100 MB

    # Database
    DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'data' / 'cloudvault.db'}"

    # Storage Provider: 'mock' or 'gcs'
    STORAGE_PROVIDER: str = "mock"
    MOCK_STORAGE_DIR: str = str(BASE_DIR / "data" / "mock_storage")

    # Google Cloud Storage (Optional)
    GCS_BUCKET_NAME: str = "cloudvault-storage"
    GCS_PROJECT_ID: str = ""
    GOOGLE_APPLICATION_CREDENTIALS: str = ""
    GCS_CREDENTIALS_JSON: str = ""  # Service account JSON string
    GCS_REGION: str = "us-central1"

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()

# Ensure local data directories exist when using SQLite or Mock Storage
if settings.DATABASE_URL.startswith("sqlite"):
    os.makedirs(BASE_DIR / "data", exist_ok=True)
if settings.STORAGE_PROVIDER == "mock":
    os.makedirs(Path(settings.MOCK_STORAGE_DIR), exist_ok=True)
