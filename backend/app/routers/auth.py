from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas import RegisterRequest, LoginRequest, TokenResponse, OTPSetupResponse
from ..services.auth_service import (
    register_voter, authenticate_voter, create_access_token,
    generate_otp_secret, get_otp_uri, get_current_otp
)
from ..models.vote import AuditLog
from ..models.user import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=OTPSetupResponse, status_code=201)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new voter. Student ID is immediately hashed with SHA-256 + salt."""
    # Check for duplicate email
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered.")

    try:
        user = register_voter(db, req.student_id, req.password, req.full_name, req.email)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    otp_uri = get_otp_uri(user.otp_secret, user.email)
    current_otp = get_current_otp(user.otp_secret)

    return OTPSetupResponse(
        otp_secret=user.otp_secret,
        otp_uri=otp_uri,
        current_otp=current_otp
    )


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """
    Authenticate voter: Student ID hash check + password + OTP.
    Three-factor authentication as specified in the proposal.
    """
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    user = authenticate_voter(db, req.student_id, req.password, req.otp_token)

    if not user:
        # Log failed attempt
        audit = AuditLog(
            event_type="login_failed",
            ip_address=ip,
            user_agent=user_agent,
            is_flagged=True,
            details="Invalid credentials or OTP"
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Student ID, password, or OTP."
        )

    # Log successful login
    audit = AuditLog(
        event_type="login_success",
        voter_id_hash=user.student_id_hash,
        ip_address=ip,
        user_agent=user_agent,
        is_flagged=False,
    )
    db.add(audit)
    db.commit()

    token = create_access_token({"sub": str(user.id), "role": user.role.value})

    return TokenResponse(
        access_token=token,
        user_id=user.id,
        full_name=user.full_name,
        role=user.role.value,
        has_voted=user.has_voted,
    )


@router.get("/otp/{user_id}")
def get_otp_for_user(user_id: int, db: Session = Depends(get_db)):
    """Dev endpoint: Get current OTP for a user (remove in production)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.otp_secret:
        raise HTTPException(status_code=404, detail="User not found")
    return {"otp": get_current_otp(user.otp_secret), "user": user.full_name}
