from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from jose import JWTError, jwt

from ..database import get_db
from ..schemas import CastVoteRequest, VoteResponse, ElectionResponse, CandidateResponse
from ..services.auth_service import decode_token, get_user_by_id
from ..services.vote_service import cast_vote
from ..models.election import Election, ElectionStatus
from ..models.candidate import Candidate
from ..models.user import User
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

router = APIRouter(prefix="/voter", tags=["Voter"])
security = HTTPBearer()


def get_current_voter(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    user = get_user_by_id(db, int(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive.")
    return user


@router.get("/ballot/{election_id}")
def get_ballot(election_id: int, db: Session = Depends(get_db), voter: User = Depends(get_current_voter)):
    """Return the ballot for the active election including candidates and public key."""
    election = db.query(Election).filter(Election.id == election_id).first()
    if not election:
        raise HTTPException(status_code=404, detail="Election not found.")
    if election.status != ElectionStatus.active:
        raise HTTPException(status_code=400, detail="Election is not currently active.")
    if voter.has_voted:
        raise HTTPException(status_code=400, detail="You have already voted in this election.")

    candidates = db.query(Candidate).filter(Candidate.election_id == election_id).all()

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
def cast_voter_vote(
    req: CastVoteRequest,
    request: Request,
    db: Session = Depends(get_db),
    voter: User = Depends(get_current_voter)
):
    """
    Cast an encrypted vote.
    Vote must be RSA-encrypted on the client side before sending.
    """
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    try:
        result = cast_vote(
            db=db,
            voter=voter,
            election_id=req.election_id,
            encrypted_vote=req.encrypted_vote,
            ip_address=ip,
            user_agent=user_agent,
            time_since_login=req.time_since_login,
            session_duration=req.session_duration,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return VoteResponse(
        success=result["success"],
        transaction_hash=result["transaction_hash"],
        message=result["message"]
    )


@router.get("/elections/active")
def get_active_elections(db: Session = Depends(get_db), voter: User = Depends(get_current_voter)):
    """List all active elections the voter can participate in."""
    from datetime import datetime
    now = datetime.utcnow()
    elections = db.query(Election).filter(Election.status == ElectionStatus.active).all()
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
def voter_status(voter: User = Depends(get_current_voter)):
    """Return current voter status."""
    return {
        "user_id": voter.id,
        "full_name": voter.full_name,
        "email": voter.email,
        "has_voted": voter.has_voted,
        "role": voter.role.value,
    }
