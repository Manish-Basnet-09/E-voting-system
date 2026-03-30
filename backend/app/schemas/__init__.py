from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


# ── Auth Schemas ──────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    student_id: str
    password: str
    full_name: str
    email: EmailStr


class LoginRequest(BaseModel):
    student_id: str
    password: str
    otp_token: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    full_name: str
    role: str
    has_voted: bool
    otp_setup_uri: Optional[str] = None


class OTPSetupResponse(BaseModel):
    otp_secret: str
    otp_uri: str
    current_otp: str  # For dev — show the current OTP


# ── Election Schemas ──────────────────────────────────────────────────────────

class ElectionCreate(BaseModel):
    title: str
    description: Optional[str] = None
    start_time: datetime
    end_time: datetime


class CandidateCreate(BaseModel):
    election_id: int
    full_name: str
    position: str
    manifesto: Optional[str] = None
    department: Optional[str] = None
    year: Optional[str] = None


class CandidateResponse(BaseModel):
    id: int
    election_id: int
    full_name: str
    position: str
    manifesto: Optional[str]
    department: Optional[str]
    year: Optional[str]

    class Config:
        from_attributes = True


class ElectionResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    status: str
    start_time: datetime
    end_time: datetime
    total_votes: int
    public_key: Optional[str] = None

    class Config:
        from_attributes = True


# ── Vote Schemas ──────────────────────────────────────────────────────────────

class CastVoteRequest(BaseModel):
    election_id: int
    encrypted_vote: str   # RSA-encrypted candidate ID
    time_since_login: float = 30.0
    session_duration: float = 60.0


class VoteResponse(BaseModel):
    success: bool
    transaction_hash: str
    message: str


# ── Admin Schemas ─────────────────────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    id: int
    event_type: str
    ip_address: Optional[str]
    anomaly_score: Optional[float]
    is_flagged: bool
    details: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_registered: int
    total_voted: int
    voter_turnout: float
    flagged_events: int
    active_elections: int
