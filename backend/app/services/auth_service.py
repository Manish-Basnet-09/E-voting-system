from datetime import datetime, timedelta
from typing import Optional
import pyotp
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from ..config import settings
from ..models.user import User, UserRole
from ..utils.hashing import generate_salt, hash_student_id, verify_student_id, hash_password, verify_password


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None


def generate_otp_secret() -> str:
    return pyotp.random_base32()


def get_otp_uri(secret: str, email: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name="PMC E-Voting")


def verify_otp(secret: str, token: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)


def get_current_otp(secret: str) -> str:
    """For development — returns current OTP token."""
    totp = pyotp.TOTP(secret)
    return totp.now()


def register_voter(db: Session, student_id: str, password: str, 
                   full_name: str, email: str) -> User:
    """Register a new voter with SHA-256 hashed student ID."""
    salt = generate_salt()
    id_hash = hash_student_id(student_id, salt)
    pwd_hash = hash_password(password)
    otp_secret = generate_otp_secret()

    user = User(
        student_id_hash=id_hash,
        salt=salt,
        password_hash=pwd_hash,
        otp_secret=otp_secret,
        full_name=full_name,
        email=email,
        role=UserRole.voter
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_voter(db: Session, student_id: str, password: str, otp_token: str) -> Optional[User]:
    """
    Authenticate voter: Student ID hash check + password + OTP.
    Implements the three-factor authentication as per proposal.
    """
    # Find all voters (we need to check against each salt)
    users = db.query(User).filter(User.role == UserRole.voter, User.is_active == True).all()
    
    matched_user = None
    for user in users:
        if verify_student_id(student_id, user.salt, user.student_id_hash):
            matched_user = user
            break

    if not matched_user:
        return None

    if not verify_password(password, matched_user.password_hash):
        return None

    if matched_user.otp_secret and not verify_otp(matched_user.otp_secret, otp_token):
        return None

    # Update last login
    matched_user.last_login = datetime.utcnow()
    db.commit()
    return matched_user


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()
