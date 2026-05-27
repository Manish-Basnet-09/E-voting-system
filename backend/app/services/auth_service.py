from datetime import datetime, timedelta
from typing import Optional
import pyotp
from jose import JWTError, jwt
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

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


async def register_voter(db: AsyncSession, student_id: str, password: str, 
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
    await db.commit()
    await db.refresh(user)
    return user


async def authenticate_voter(db: AsyncSession, student_id: str, password: str, otp_token: str) -> Optional[User]:
    stmt = select(User).where(User.role == UserRole.voter, User.is_active == True)
    result = await db.execute(stmt)
    users = result.scalars().all()
    
    print(f"DEBUG: Found {len(users)} active voters.") # See if users are even being found

    matched_user = None
    for user in users:
        # Check if the student_id matches (using your hashing utility)
        if verify_student_id(student_id, user.salt, user.student_id_hash):
            matched_user = user
            print(f"DEBUG: Found match for Student ID: {student_id}")
            break
    
    if not matched_user:
        print("DEBUG: No user matched the provided Student ID.")
        return None

    if not verify_password(password, matched_user.password_hash):
        print(f"DEBUG: Password verification failed for {matched_user.full_name}")
        return None

    # OTP validation (with your new '123456' bypass)
    if matched_user.otp_secret:
        if otp_token == "123456":
            print("DEBUG: OTP Bypass used successfully.")
        elif not verify_otp(matched_user.otp_secret, otp_token):
            print(f"DEBUG: OTP verification failed for {matched_user.full_name}")
            return None

    matched_user.last_login = datetime.utcnow()
    await db.commit()
    print("DEBUG: Login success!")
    return matched_user


async def get_user_by_id(db: AsyncSession, user_id: int) -> Optional[User]:
    """Fetch user by primary index ID key asynchronously."""
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    return result.scalars().first()



async def verify_session(db: AsyncSession, payload: dict) -> User:
    """
    Validates the unique session token inside the JWT payload against the database.
    If another device logged in afterward, this token will mismatch and trigger a kick.
    """
    user_id = payload.get("sub")
    token_session = payload.get("session_token")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token payload."
        )

    user = await get_user_by_id(db, int(user_id))
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer exists."
        )

    # If the user's active token doesn't match the browser token, boot them out!
    if user.current_session_token != token_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session Overwritten: Another device has logged into this account. You have been disconnected."
        )

    return user