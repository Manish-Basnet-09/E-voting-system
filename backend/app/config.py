from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    app_name: str = "E-Voting System - Patan Multiple Campus"
    app_version: str = "1.0.0"
    debug: bool = True

    # Database
    database_url: str = "sqlite:///./evoting.db"

    # JWT
    jwt_secret_key: str = "dev-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # OTP
    otp_secret_key: str = "dev-otp-key"
    otp_valid_seconds: int = 300

    # RSA
    rsa_private_key_path: str = "./private_key.pem"
    rsa_public_key_path: str = "./public_key.pem"
    rsa_key_size: int = 2048

    # Hashing
    hash_pepper: str = "dev-pepper-evoting-pmc"

    # ML
    isolation_forest_contamination: float = 0.05
    anomaly_score_threshold: float = 0.7

    # CORS
    allowed_origins: str = "http://localhost:3000"

    class Config:
        env_file = ".env"


settings = Settings()
