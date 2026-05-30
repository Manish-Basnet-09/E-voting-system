from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Enum
from sqlalchemy.sql import func
import enum
from ..database import Base


class ElectionStatus(str, enum.Enum):
    upcoming = "upcoming"
    active = "active"
    closed = "closed"
    results_published = "results_published"


class Election(Base):
    __tablename__  = "elections"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(Enum(ElectionStatus), default=ElectionStatus.upcoming)
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True), nullable=False)
    public_key = Column(Text, nullable=True)   # RSA public key (PEM)
    private_key = Column(Text, nullable=True)  # RSA private key (PEM) — hidden until publish
    total_votes = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    created_by = Column(Integer, nullable=True)