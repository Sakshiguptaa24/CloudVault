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

    # Storage Provider & Multi-Cloud Routing: 'mock', 'gcs', 's3', 'azure'
    STORAGE_PROVIDER: str = "mock"
    STORAGE_SECONDARY_PROVIDER: str = "s3"
    STORAGE_FAILOVER_ENABLED: bool = True
    STORAGE_MAX_RETRIES: int = 3
    STORAGE_RETRY_BACKOFF: float = 0.5
    STORAGE_TIMEOUT_SECONDS: int = 10
    MOCK_STORAGE_DIR: str = str(BASE_DIR / "data" / "mock_storage")

    # Google Cloud Storage (Optional)
    GCS_BUCKET_NAME: str = "cloudvault-storage"
    GCS_PROJECT_ID: str = ""
    GOOGLE_APPLICATION_CREDENTIALS: str = ""
    GCS_CREDENTIALS_JSON: str = ""  # Service account JSON string
    GCS_REGION: str = "us-central1"

    # AWS S3 (Optional)
    AWS_S3_BUCKET: str = "cloudvault-s3-backup"
    AWS_REGION: str = "us-east-1"
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""

    # Azure Blob Storage (Optional)
    AZURE_CONTAINER: str = "cloudvault-backups"
    AZURE_STORAGE_CONNECTION_STRING: str = ""

    # AI Anomaly & Ransomware Detection Thresholds
    RANSOMWARE_ENTROPY_THRESHOLD: float = 7.50
    RISK_THRESHOLD_SUSPICIOUS: int = 30
    RISK_THRESHOLD_HIGH: int = 60
    RISK_THRESHOLD_CRITICAL: int = 80
    BURST_MODIFICATION_COUNT: int = 20
    DELETION_BURST_THRESHOLD: int = 15

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()

# Ensure local data directories exist when using SQLite or Mock Storage
if settings.DATABASE_URL.startswith("sqlite"):
    os.makedirs(BASE_DIR / "data", exist_ok=True)
if settings.STORAGE_PROVIDER == "mock":
    os.makedirs(Path(settings.MOCK_STORAGE_DIR), exist_ok=True)
