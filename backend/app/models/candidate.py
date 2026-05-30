from sqlalchemy import Column, Integer, String, ForeignKey, Text, DateTime
from sqlalchemy.sql import func
from ..database import Base


class Candidate(Base):
    __tablename__ = "candidates"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(Integer, ForeignKey("elections.id"), nullable=False)
    full_name = Column(String(100), nullable=False)
    position = Column(String(100), nullable=False)
    manifesto = Column(Text, nullable=True)
    department = Column(String(100), nullable=True)
    year = Column(String(20), nullable=True)
    
    # 🌟 Keep at 0 during the election to protect ballot secrecy, 
    # update exclusively via an aggregate tally script when the election closes.
    vote_count = Column(Integer, default=0)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())