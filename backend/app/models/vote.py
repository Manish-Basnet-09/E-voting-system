from sqlalchemy import Column, Integer, String, ForeignKey, Text, Float, Boolean, DateTime
from sqlalchemy.sql import func
from ..database import Base


class Vote(Base):
    __tablename__ = "votes"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(Integer, ForeignKey("elections.id"), nullable=False)
    voter_id_hash = Column(String(128), nullable=False)   # SHA-256 hash — anonymized
    encrypted_vote = Column(Text, nullable=False)         # RSA-encrypted candidate ID
    transaction_hash = Column(String(128), unique=True)   # SHA-256 integrity seal
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    cast_at = Column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False)   # login, vote_cast, anomaly_flag
    voter_id_hash = Column(String(128), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    anomaly_score = Column(Float, nullable=True)
    is_flagged = Column(Boolean, default=False)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
