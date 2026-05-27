from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func
from typing import List, Optional
from datetime import datetime

from ..database import get_db
from ..schemas import ElectionCreate, CandidateCreate, DashboardStats
from ..services.auth_service import decode_token
from ..services.vote_service import tabulate_results
from ..models.election import Election, ElectionStatus
from ..models.candidate import Candidate
from ..models.user import User, UserRole
from ..models.vote import AuditLog
from ..utils.crypto import generate_rsa_keypair
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

router = APIRouter(prefix="/admin", tags=["Admin"])
security = HTTPBearer()

# ── Admin Authentication Dependency ──────────────────────────────────────────

async def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token.")
    
    result = await db.execute(select(User).filter(User.id == int(payload["sub"])))
    user = result.scalar_one_or_none()
    
    if not user or user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    return user

# ── Dashboard ────────────────────────────────────────────────────────────────

@router.get("/dashboard", response_model=DashboardStats)
async def get_dashboard(db: AsyncSession = Depends(get_db), admin: User = Depends(get_current_admin)):
    total_registered = await db.scalar(select(func.count(User.id)).filter(User.role == UserRole.voter))
    total_voted = await db.scalar(select(func.count(User.id)).filter(User.role == UserRole.voter, User.has_voted == True))
    flagged = await db.scalar(select(func.count(AuditLog.id)).filter(AuditLog.is_flagged == True))
    active_elections = await db.scalar(select(func.count(Election.id)).filter(Election.status == ElectionStatus.active))
    
    turnout = round((total_voted / total_registered * 100) if total_registered > 0 else 0, 2)
    
    return DashboardStats(
        total_registered=total_registered or 0,
        total_voted=total_voted or 0,
        voter_turnout=turnout,
        flagged_events=flagged or 0,
        active_elections=active_elections or 0
    )

# ── Election Management ───────────────────────────────────────────────────────

@router.post("/elections", status_code=201)
async def create_election(req: ElectionCreate, db: AsyncSession = Depends(get_db), admin: User = Depends(get_current_admin)):
    public_key, private_key = generate_rsa_keypair()
    election = Election(
        **req.model_dump(), 
        status=ElectionStatus.upcoming, 
        public_key=public_key, 
        private_key=private_key, 
        created_by=admin.id
    )
    db.add(election)
    await db.commit()
    return {"election_id": election.id, "title": election.title}

@router.get("/elections")
async def list_elections(db: AsyncSession = Depends(get_db), admin: User = Depends(get_current_admin)):
    result = await db.execute(select(Election).order_by(Election.created_at.desc()))
    return result.scalars().all()

# ── Candidate Management ──────────────────────────────────────────────────────

@router.post("/candidate", status_code=201)
async def add_candidate(req: CandidateCreate, db: AsyncSession = Depends(get_db), admin: User = Depends(get_current_admin)):
    candidate = Candidate(**req.model_dump())
    db.add(candidate)
    await db.commit()
    return {"candidate_id": candidate.id}

@router.delete("/candidate/{candidate_id}")
async def delete_candidate(candidate_id: int, db: AsyncSession = Depends(get_db), admin: User = Depends(get_current_admin)):
    result = await db.execute(select(Candidate).filter(Candidate.id == candidate_id))
    c = result.scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Candidate not found.")
    await db.delete(c)
    await db.commit()
    return {"message": "Candidate removed."}

# ── Voter Management ──────────────────────────────────────────────────────────

@router.get("/voters")
async def list_voters(db: AsyncSession = Depends(get_db), admin: User = Depends(get_current_admin)):
    result = await db.execute(select(User).filter(User.role == UserRole.voter))
    return result.scalars().all()

@router.patch("/voters/{voter_id}/toggle-active")
async def toggle_voter_status(voter_id: int, db: AsyncSession = Depends(get_db), admin: User = Depends(get_current_admin)):
    result = await db.execute(select(User).filter(User.id == voter_id))
    voter = result.scalar_one_or_none()
    if not voter:
        raise HTTPException(status_code=404, detail="Voter record not found.")
    voter.is_active = not voter.is_active
    await db.commit()
    return {"status": "success", "is_active": voter.is_active}

# ── Results & Audit ───────────────────────────────────────────────────────────

# MATCHED URL PATH: Perfectly mirrors the frontend dashboard fetch call route syntax
@router.post("/results/{election_id}")
async def get_results(election_id: int, db: AsyncSession = Depends(get_db), admin: User = Depends(get_current_admin)):
    result = await db.execute(select(Election).filter(Election.id == election_id))
    election = result.scalar_one_or_none()
    if not election or not election.private_key:
        raise HTTPException(status_code=404, detail="Election or key invalid.")
    
    # Executing the asynchronous database decryption tabulation engine securely
    results = await tabulate_results(db, election_id, election.private_key)
    election.status = ElectionStatus.results_published
    await db.commit()
    return results

@router.get("/audit-logs")
async def get_audit_logs(
    limit: int = 50, 
    flagged_only: bool = False, 
    db: AsyncSession = Depends(get_db), 
    admin: User = Depends(get_current_admin)
):
    query = select(AuditLog)
    if flagged_only:
        query = query.filter(AuditLog.is_flagged == True)
    query = query.order_by(AuditLog.created_at.desc()).limit(limit)
    
    result = await db.execute(query)
    return result.scalars().all()