import os
from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent.parent

KNOWN_INSECURE_DEFAULT_SECRET = "cloudvault-super-secret-key-change-in-production-2026"

class Settings(BaseSettings):
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    ENVIRONMENT: str = "development"  # 'development', 'testing', 'staging', 'production'

    # Security
    SECRET_KEY: str = KNOWN_INSECURE_DEFAULT_SECRET
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

    # Rate Limiting Controls
    RATE_LIMIT_LOGIN_MAX_ATTEMPTS: int = 5
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: int = 300       # 5 minutes
    RATE_LIMIT_REGISTER_MAX_ATTEMPTS: int = 10
    RATE_LIMIT_REGISTER_WINDOW_SECONDS: int = 3600    # 1 hour

    class Config:
        env_file = ".env"
        extra = "allow"

    def is_production(self) -> bool:
        """Return True if running in production mode."""
        return self.ENVIRONMENT.lower() in ("production", "prod")

    def validate_security_configuration(self) -> None:
        """
        Validate cryptographic secrets and origins in production mode.
        Fails safely without printing secret values in logs or exception messages.
        """
        if not self.is_production():
            return

        # 1. Validate SECRET_KEY in production
        if not self.SECRET_KEY or self.SECRET_KEY == KNOWN_INSECURE_DEFAULT_SECRET:
            raise RuntimeError(
                "Insecure production configuration: SECRET_KEY cannot use the default placeholder. "
                "Configure a secure, cryptographically random SECRET_KEY (at least 32 bytes) in environment variables."
            )

        if len(self.SECRET_KEY) < 32:
            raise RuntimeError(
                f"Insecure production configuration: SECRET_KEY must be at least 32 characters long "
                f"(current length: {len(self.SECRET_KEY)})."
            )

        # 2. Validate ALLOWED_ORIGINS in production
        raw_origins = [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]
        if not raw_origins or "*" in raw_origins:
            raise RuntimeError(
                "Insecure production configuration: ALLOWED_ORIGINS cannot be empty or wildcard '*' in production. "
                "Specify explicit HTTPS domain(s), e.g. 'https://my-cloudvault.streamlit.app'."
            )

        for orig in raw_origins:
            if not orig.startswith("https://"):
                raise RuntimeError(
                    f"Insecure production configuration: Origin must use secure HTTPS protocol. Insecure origin: {orig}"
                )
            if "localhost" in orig.lower() or "127.0.0.1" in orig:
                raise RuntimeError(
                    f"Insecure production configuration: Production origins cannot point to localhost: {orig}"
                )

    def validate_storage_configuration(self) -> None:
        """
        Enforce durable persistent object storage in production.
        Rejects ephemeral mock filesystem storage to prevent data loss on container restart.
        """
        if not self.is_production():
            return

        provider = self.STORAGE_PROVIDER.lower().strip()
        if provider == "mock":
            raise RuntimeError(
                "Production durability violation: STORAGE_PROVIDER cannot be 'mock' in production. "
                "Ephemeral container storage will wipe user data on restart. "
                "Configure a durable persistent cloud provider: 'gcs', 's3', or 'azure'."
            )

        if provider not in ("gcs", "s3", "azure"):
            raise RuntimeError(
                f"Unsupported production storage provider: '{self.STORAGE_PROVIDER}'. "
                "Must be one of: 'gcs', 's3', 'azure'."
            )

        if provider == "gcs" and not self.GCS_BUCKET_NAME:
            raise RuntimeError("Production GCS storage configuration missing required GCS_BUCKET_NAME.")
        if provider == "s3" and not self.AWS_S3_BUCKET:
            raise RuntimeError("Production AWS S3 storage configuration missing required AWS_S3_BUCKET.")
        if provider == "azure" and not self.AZURE_CONTAINER:
            raise RuntimeError("Production Azure storage configuration missing required AZURE_CONTAINER.")

        if self.STORAGE_FAILOVER_ENABLED and self.STORAGE_SECONDARY_PROVIDER.lower().strip() == "mock":
            raise RuntimeError(
                "Production failover violation: STORAGE_SECONDARY_PROVIDER cannot be 'mock' in production. "
                "Configure a valid persistent secondary cloud provider."
            )

    def validate_production_rules(self) -> None:
        """Run all production security and durability assertions."""
        if self.is_production():
            self.validate_security_configuration()
            self.validate_storage_configuration()


settings = Settings()

# Ensure local data directories exist when using SQLite or Mock Storage
if settings.DATABASE_URL.startswith("sqlite"):
    os.makedirs(BASE_DIR / "data", exist_ok=True)
if settings.STORAGE_PROVIDER == "mock":
    os.makedirs(Path(settings.MOCK_STORAGE_DIR), exist_ok=True)
