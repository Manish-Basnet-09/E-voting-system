from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import update 
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ..database import get_db
from ..schemas import CastVoteRequest, VoteResponse
from .auth import get_current_user  
from ..services.vote_service import cast_vote
from ..models.election import Election, ElectionStatus
from ..models.candidate import Candidate
from ..models.user import User

# 
router = APIRouter(prefix="/voter", tags=["Voter"])


@router.get("/ballot/{election_id}")
async def get_ballot(
    election_id: int, 
    db: AsyncSession = Depends(get_db), 
    voter: User = Depends(get_current_user)
):
    """Return the ballot for the active election including candidates and public key."""
    result = await db.execute(select(Election).filter(Election.id == election_id))
    election = result.scalars().first()
    
    if not election:
        raise HTTPException(status_code=404, detail="Election matrix index not found.")
    if election.status != ElectionStatus.active:
        raise HTTPException(status_code=400, detail="Requested target election is not currently active.")
    
    if voter.has_voted:
        raise HTTPException(status_code=400, detail="Security violation: Account has already cast a ballot.")

    if voter.verification_code is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Please verify your 6-digit email confirmation code before viewing the ballot."
        )

    cand_result = await db.execute(select(Candidate).filter(Candidate.election_id == election_id))
    candidates = cand_result.scalars().all()

    return {
        "election": {
            "id": election.id,
            "title": election.title,
            "description": election.description,
            "end_time": election.end_time.isoformat(),
            "public_key": election.public_key,
        },
        "candidates": [
            {
                "id": c.id,
                "full_name": c.full_name,
                "position": c.position,
                "manifesto": c.manifesto,
                "department": c.department,
                "year": c.year,
            }
            for c in candidates
        ],
        "voter": {
            "full_name": voter.full_name,
            "has_voted": voter.has_voted,
        }
    }


@router.post("/cast", response_model=VoteResponse)
async def cast_voter_vote(
    req: CastVoteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    voter: User = Depends(get_current_user)
):
    """Cast an encrypted vote and forcefully update voter eligibility status."""
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    # Apply row-level locking (FOR UPDATE) right at the transaction start
    voter_query = await db.execute(
        select(User).filter(User.id == voter.id).with_for_update()
    )
    locked_voter = voter_query.scalars().first()

    if not locked_voter or locked_voter.has_voted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Transaction Rejected: Ballot submission already recorded for this voter."
        )

    try:
        # 1. Execute core business logic (dropping anonymized vote, processing ML features)
        result = await cast_vote(
            db=db,
            voter=locked_voter,
            election_id=req.election_id,
            encrypted_vote=req.encrypted_vote,
            ip_address=ip,
            user_agent=user_agent,
            time_since_login=req.time_since_login,
            session_duration=req.session_duration,
        )
        
        # 🌟 2. DIRECT SQL FORCE-WRITE OVERRIDE
        # Bypasses any async tracking maps by forcing a explicit update statement 
        await db.execute(
            update(User)
            .where(User.id == voter.id)
            .values(has_voted=True)
        )
        
        # 🌟 3. COMMIT AT THE ROUTER BOUNDARY
        await db.commit()

    except ValueError as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database state mutation crash: {str(e)}")

    return VoteResponse(
        success=result["success"],
        transaction_hash=result["transaction_hash"],
        message=result["message"]
    )


@router.get("/elections/active")
async def get_active_elections(
    db: AsyncSession = Depends(get_db), 
    voter: User = Depends(get_current_user)
):
    """List all active elections the voter can participate in."""
    result = await db.execute(select(Election).filter(Election.status == ElectionStatus.active))
    elections = result.scalars().all()
    return [
        {
            "id": e.id,
            "title": e.title,
            "description": e.description,
            "end_time": e.end_time.isoformat(),
            "total_votes": e.total_votes,
        }
        for e in elections
    ]


@router.get("/status")
async def voter_status(voter: User = Depends(get_current_user)):
    """Return current voter status metrics."""
    return {
        "user_id": voter.id,
        "full_name": voter.full_name,
        "email": voter.email,
        "has_voted": voter.has_voted,
        "role": voter.role.value,
    }