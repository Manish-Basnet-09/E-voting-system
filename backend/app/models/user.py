from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum
from sqlalchemy.sql import func
import enum
from ..database import Base


class UserRole(str, enum.Enum):
    voter = "voter"
    admin = "admin"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    student_id_hash = Column(String(128), unique=True, index=True, nullable=False)
    salt = Column(String(64), nullable=False)
    password_hash = Column(String(128), nullable=False)
    otp_secret = Column(String(32), nullable=True)
    full_name = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, index=True, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.voter, nullable=False)
    is_active = Column(Boolean, default=True)
    has_voted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
