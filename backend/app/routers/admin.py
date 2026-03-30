from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from datetime import datetime

from ..database import get_db
from ..schemas import ElectionCreate, CandidateCreate, DashboardStats, AuditLogResponse
from ..services.auth_service import decode_token, get_user_by_id
from ..services.vote_service import tabulate_results
from ..models.election import Election, ElectionStatus
from ..models.candidate import Candidate
from ..models.user import User, UserRole
from ..models.vote import AuditLog, Vote
from ..utils.crypto import generate_rsa_keypair
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

router = APIRouter(prefix="/admin", tags=["Admin"])
security = HTTPBearer()


def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token.")
    user = get_user_by_id(db, int(payload["sub"]))
    if not user or user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    return user


# ── Dashboard ────────────────────────────────────────────────────────────────

@router.get("/dashboard", response_model=DashboardStats)
def get_dashboard(db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    """Real-time admin monitoring dashboard."""
    total_registered = db.query(User).filter(User.role == UserRole.voter).count()
    total_voted = db.query(User).filter(User.role == UserRole.voter, User.has_voted == True).count()
    flagged = db.query(AuditLog).filter(AuditLog.is_flagged == True).count()
    active_elections = db.query(Election).filter(Election.status == ElectionStatus.active).count()
    turnout = round((total_voted / total_registered * 100) if total_registered > 0 else 0, 2)

    return DashboardStats(
        total_registered=total_registered,
        total_voted=total_voted,
        voter_turnout=turnout,
        flagged_events=flagged,
        active_elections=active_elections,
    )


# ── Election Management ───────────────────────────────────────────────────────

@router.post("/election", status_code=201)
def create_election(req: ElectionCreate, db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    """Create and configure a new election with RSA key pair generation."""
    public_key, private_key = generate_rsa_keypair()

    election = Election(
        title=req.title,
        description=req.description,
        start_time=req.start_time,
        end_time=req.end_time,
        status=ElectionStatus.upcoming,
        public_key=public_key,
        private_key=private_key,
        created_by=admin.id,
    )
    db.add(election)
    db.commit()
    db.refresh(election)
    return {"election_id": election.id, "title": election.title, "status": election.status}


@router.patch("/election/{election_id}/activate")
def activate_election(election_id: int, db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    election = db.query(Election).filter(Election.id == election_id).first()
    if not election:
        raise HTTPException(status_code=404, detail="Election not found.")
    election.status = ElectionStatus.active
    db.commit()
    return {"message": f"Election '{election.title}' is now ACTIVE."}


@router.patch("/election/{election_id}/close")
def close_election(election_id: int, db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    election = db.query(Election).filter(Election.id == election_id).first()
    if not election:
        raise HTTPException(status_code=404, detail="Election not found.")
    election.status = ElectionStatus.closed
    db.commit()
    return {"message": f"Election '{election.title}' has been CLOSED."}


@router.get("/elections")
def list_elections(db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    elections = db.query(Election).order_by(Election.created_at.desc()).all()
    return [
        {
            "id": e.id, "title": e.title, "status": e.status,
            "start_time": e.start_time, "end_time": e.end_time,
            "total_votes": e.total_votes,
        }
        for e in elections
    ]


# ── Candidate Management ──────────────────────────────────────────────────────

@router.post("/candidate", status_code=201)
def add_candidate(req: CandidateCreate, db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    candidate = Candidate(**req.model_dump())
    db.add(candidate)
    db.commit()
    db.refresh(candidate)
    return {"candidate_id": candidate.id, "full_name": candidate.full_name}


@router.get("/candidates/{election_id}")
def get_candidates(election_id: int, db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    candidates = db.query(Candidate).filter(Candidate.election_id == election_id).all()
    return candidates


@router.delete("/candidate/{candidate_id}")
def delete_candidate(candidate_id: int, db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    c = db.query(Candidate).filter(Candidate.id == candidate_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Candidate not found.")
    db.delete(c)
    db.commit()
    return {"message": "Candidate removed."}


# ── Voter Management ──────────────────────────────────────────────────────────

@router.get("/voters")
def list_voters(db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    voters = db.query(User).filter(User.role == UserRole.voter).all()
    return [
        {
            "id": v.id, "full_name": v.full_name, "email": v.email,
            "has_voted": v.has_voted, "is_active": v.is_active,
            "created_at": v.created_at,
        }
        for v in voters
    ]


@router.post("/voter/create-admin")
def create_admin_user(req: dict, db: Session = Depends(get_db)):
    """Bootstrap endpoint to create the first admin (no auth required — disable after setup)."""
    from ..services.auth_service import register_voter
    from ..utils.hashing import hash_password
    from ..services.auth_service import generate_otp_secret
    from ..utils.hashing import generate_salt, hash_student_id

    salt = generate_salt()
    id_hash = hash_student_id(req.get("student_id", "ADMIN001"), salt)
    pwd_hash = hash_password(req.get("password", "Admin@123"))
    otp_secret = generate_otp_secret()

    admin = User(
        student_id_hash=id_hash,
        salt=salt,
        password_hash=pwd_hash,
        otp_secret=otp_secret,
        full_name=req.get("full_name", "System Admin"),
        email=req.get("email", "admin@pmc.edu.np"),
        role=UserRole.admin,
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)
    from ..services.auth_service import get_otp_uri, get_current_otp
    return {
        "admin_id": admin.id,
        "otp_secret": otp_secret,
        "current_otp": get_current_otp(otp_secret),
        "message": "Admin created. Disable this endpoint in production!"
    }


# ── Results & Audit ───────────────────────────────────────────────────────────

@router.post("/results/{election_id}")
def get_results(election_id: int, db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    """Decrypt and tabulate votes using the election's private key."""
    election = db.query(Election).filter(Election.id == election_id).first()
    if not election:
        raise HTTPException(status_code=404, detail="Election not found.")
    if election.status == ElectionStatus.active:
        raise HTTPException(status_code=400, detail="Cannot tabulate results while election is active.")
    if not election.private_key:
        raise HTTPException(status_code=400, detail="Private key not found for this election.")

    try:
        results = tabulate_results(db, election_id, election.private_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption error: {str(e)}")

    election.status = ElectionStatus.results_published
    db.commit()
    return results


@router.get("/audit-logs")
def get_audit_logs(
    limit: int = 50,
    flagged_only: bool = False,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    """Access logs generated by the fraud detection engine."""
    query = db.query(AuditLog)
    if flagged_only:
        query = query.filter(AuditLog.is_flagged == True)
    logs = query.order_by(AuditLog.created_at.desc()).limit(limit).all()
    return [
        {
            "id": l.id,
            "event_type": l.event_type,
            "ip_address": l.ip_address,
            "anomaly_score": l.anomaly_score,
            "is_flagged": l.is_flagged,
            "details": l.details,
            "created_at": l.created_at,
        }
        for l in logs
    ]
