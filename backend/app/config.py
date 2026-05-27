from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import EmailStr

# 🌟 DYNAMIC ABSOLUTE PATH CALCULATOR
# __file__ is: E-voting-system/backend/app/config.py
# parent is: E-voting-system/backend/app/
# parent.parent is: E-voting-system/backend/
# parent.parent.parent is the root: E-voting-system/
BASE_DIR = Path(__file__).resolve().parent.parent.parent
ENV_FILE_PATH = BASE_DIR / ".env"


class Settings(BaseSettings):
    # App Settings
    app_name: str = "E-Voting System - Patan Multiple Campus"
    app_version: str = "1.0.0"
    debug: bool = True

    # Database
    database_url: str = "sqlite:///./evoting.db"  # Will be overridden by your .env PostgreSQL URL

    # JWT Security
    jwt_secret_key: str = "dev-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # OTP Core
    otp_secret_key: str = "dev-otp-key"
    otp_valid_seconds: int = 300

    # RSA Cryptography Protocols
    rsa_private_key_path: str = "./private_key.pem"
    rsa_public_key_path: str = "./public_key.pem"
    rsa_key_size: int = 2048

    # Hashing Layer
    hash_pepper: str = "dev-pepper-evoting-pmc"

    # Machine Learning Anomaly Detection Settings
    isolation_forest_contamination: float = 0.05
    anomaly_score_threshold: float = 0.7

    # CORS Communication Parameters
    allowed_origins: str = "http://localhost:3000"

    # ─── ADDED: SMTP EMAIL VERIFICATION SETTINGS ───
    mail_username: EmailStr
    mail_password: str
    mail_from: EmailStr
    mail_port: int = 587
    mail_server: str = "smtp.gmail.com"

    # Pydantic Configuration Strategy Matrix
    model_config = SettingsConfigDict(
        # 🌟 Point Pydantic directly to the absolute path of the root .env file
        env_file=ENV_FILE_PATH,
        env_file_encoding="utf-8",
        extra="ignore",          # Crucial: stops 'extra_forbidden' validation crashes
        case_sensitive=False     # Maps database_url to DATABASE_URL seamlessly
    )


settings = Settings()