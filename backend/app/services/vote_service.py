from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from typing import Optional

from ..models.vote import Vote, AuditLog
from ..models.candidate import Candidate
from ..models.election import Election, ElectionStatus
from ..models.user import User
from ..utils.crypto import decrypt_vote
from ..utils.hashing import generate_transaction_hash
from ..ml.anomaly_detector import detector


async def cast_vote(
    db: AsyncSession,
    voter: User,  # Receives pre-locked instance cleanly from the caller route
    election_id: int,
    encrypted_vote: str,
    ip_address: str,
    user_agent: str,
    time_since_login: float,
    session_duration: float,
) -> dict:
    """
    Validates and queues state data mutations for a vote casting event.
    ⚠️ Relies entirely on the calling router context to commit the transaction.
    """
    
    if not voter:
        raise ValueError("Voter identification profile not found in active database session.")

    # Strict Double-Voting enforcement check against live database state
    if voter.has_voted:
        raise ValueError("You have already cast your vote in this election.")

    # Check election status asynchronously and apply row lock
    elec_result = await db.execute(
        select(Election).filter(
            Election.id == election_id,
            Election.status == ElectionStatus.active
        ).with_for_update()
    )
    election = elec_result.scalars().first()
    if not election:
        raise ValueError("Election is not currently active.")

    # Gather data points for Machine Learning Fraud Vector Model
    ip_count_result = await db.execute(
        select(func.count(Vote.id)).filter(Vote.ip_address == ip_address)
    )
    votes_from_ip = ip_count_result.scalar_one_or_none() or 0
    
    features = detector.extract_features(
        ip_address=ip_address,
        user_agent=user_agent or "",
        time_since_login=time_since_login,
        login_hour=datetime.utcnow().hour,
        votes_from_ip=votes_from_ip,
        session_duration=session_duration,
    )
    is_flagged, anomaly_score = detector.is_anomalous(features)
    detector.add_training_sample(features)

    # Generate transaction hash (Digital seal containing timestamp and ciphertext)
    timestamp = datetime.utcnow().isoformat()
    transaction_hash = generate_transaction_hash(
        election_id, encrypted_vote, timestamp
    )

    # Drop the vote into the database (100% Anonymized)
    vote = Vote(
        election_id=election_id,
        encrypted_vote=encrypted_vote,
        transaction_hash=transaction_hash,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(vote)

    # Update in-memory worker object state layout
    voter.has_voted = True
    db.add(voter)

    # Increment public non-identifiable counter 
    election.total_votes += 1
    db.add(election)

    # Log the security footprint trace without storing voter identity metrics
    audit = AuditLog(
        event_type="vote_cast",
        voter_id_hash=None, 
        ip_address=ip_address,
        user_agent=user_agent,
        anomaly_score=anomaly_score,
        is_flagged=is_flagged,
        details=f"Transaction Seal: {transaction_hash[:16]}..."
    )
    db.add(audit)
    
    # 🌟 Push down staged model updates to pipeline without terminating context
    await db.flush()

    return {
        "success": True,
        "transaction_hash": transaction_hash,
        "is_flagged": is_flagged,
        "anomaly_score": round(anomaly_score, 4),
        "message": "Your vote has been cast and encrypted successfully."
    }


async def tabulate_results(db: AsyncSession, election_id: int, private_key_pem: str) -> dict:
    """
    Decrypt and tally all votes for an election at close phase.
    """
    vote_result = await db.execute(select(Vote).filter(Vote.election_id == election_id))
    votes = vote_result.scalars().all()
    
    cand_result = await db.execute(select(Candidate).filter(Candidate.election_id == election_id))
    candidates = cand_result.scalars().all()
    
    counts = {str(c.id): 0 for c in candidates}

    errors = 0
    for vote in votes:
        try:
            decrypted = decrypt_vote(vote.encrypted_vote, private_key_pem)
            candidate_id = decrypted.strip()
            if candidate_id in counts:
                counts[candidate_id] += 1
            else:
                errors += 1
        except Exception:
            errors += 1

    for candidate in candidates:
        candidate.vote_count = counts.get(str(candidate.id), 0)
        db.add(candidate)
        
    await db.flush()

    results = []
    for c in sorted(candidates, key=lambda x: -x.vote_count):
        results.append({
            "candidate_id": c.id,
            "full_name": c.full_name,
            "position": c.position,
            "department": c.department,
            "vote_count": counts.get(str(c.id), 0),
        })

    return {
        "election_id": election_id,
        "total_votes": len(votes),
        "decryption_errors": errors,
        "results": results
    }