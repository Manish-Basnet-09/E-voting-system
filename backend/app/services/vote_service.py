from datetime import datetime
from sqlalchemy.orm import Session
from typing import Optional

from ..models.vote import Vote, AuditLog
from ..models.candidate import Candidate
from ..models.election import Election, ElectionStatus
from ..models.user import User
from ..utils.crypto import decrypt_vote
from ..utils.hashing import generate_transaction_hash
from ..ml.anomaly_detector import detector


def cast_vote(
    db: Session,
    voter: User,
    election_id: int,
    encrypted_vote: str,
    ip_address: str,
    user_agent: str,
    time_since_login: float,
    session_duration: float,
) -> dict:
    """
    Cast an encrypted vote after all validations.
    
    Flow:
    1. Check election is active
    2. Check voter hasn't voted (One-ID-One-Vote)
    3. Run anomaly detection
    4. Store encrypted vote + transaction hash
    5. Update voter status
    """
    # Check election status
    election = db.query(Election).filter(
        Election.id == election_id,
        Election.status == ElectionStatus.active
    ).first()
    if not election:
        raise ValueError("Election is not currently active.")

    # One-ID-One-Vote enforcement
    if voter.has_voted:
        raise ValueError("You have already cast your vote in this election.")

    # Check if this voter already has a vote record
    existing_vote = db.query(Vote).filter(
        Vote.election_id == election_id,
        Vote.voter_id_hash == voter.student_id_hash
    ).first()
    if existing_vote:
        raise ValueError("A vote has already been recorded for this ID.")

    # Run anomaly detection
    votes_from_ip = db.query(Vote).filter(Vote.ip_address == ip_address).count()
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

    # Generate transaction hash (digital seal for this vote)
    timestamp = datetime.utcnow().isoformat()
    transaction_hash = generate_transaction_hash(
        voter.student_id_hash, election_id, encrypted_vote, timestamp
    )

    # Store the vote (anonymized — only hash, not student ID)
    vote = Vote(
        election_id=election_id,
        voter_id_hash=voter.student_id_hash,
        encrypted_vote=encrypted_vote,
        transaction_hash=transaction_hash,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(vote)

    # Update voter status (One-ID-One-Vote enforcement)
    voter.has_voted = True

    # Update election vote count
    election.total_votes += 1

    # Log the audit event
    audit = AuditLog(
        event_type="vote_cast",
        voter_id_hash=voter.student_id_hash,
        ip_address=ip_address,
        user_agent=user_agent,
        anomaly_score=anomaly_score,
        is_flagged=is_flagged,
        details=f"Transaction: {transaction_hash[:16]}..."
    )
    db.add(audit)
    db.commit()

    return {
        "success": True,
        "transaction_hash": transaction_hash,
        "is_flagged": is_flagged,
        "anomaly_score": round(anomaly_score, 4),
        "message": "Your vote has been cast and encrypted successfully."
    }


def tabulate_results(db: Session, election_id: int, private_key_pem: str) -> dict:
    """
    Decrypt and tally all votes for an election.
    Uses RSA private key for decryption.
    """
    votes = db.query(Vote).filter(Vote.election_id == election_id).all()
    candidates = db.query(Candidate).filter(Candidate.election_id == election_id).all()
    
    # Reset counts
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

    # Update candidate vote counts
    for candidate in candidates:
        candidate.vote_count = counts.get(str(candidate.id), 0)
    db.commit()

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
