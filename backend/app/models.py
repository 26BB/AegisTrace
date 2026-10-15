from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from backend.app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    case_number = Column(String(64), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    victim_alias = Column(String(128), default="Victim-Anonymous")
    suspect_alias = Column(String(128), default="Unknown Suspect")
    platform = Column(String(64), default="Multi-Vector")
    threat_score = Column(Float, default=0.0)
    risk_tier = Column(String(32), default="LOW")
    summary = Column(Text, nullable=True)
    analysis_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    # Relationships
    messages = relationship("Message", back_populates="incident", cascade="all, delete-orphan")
    forensic_traces = relationship("ForensicTrace", back_populates="incident", cascade="all, delete-orphan")
    evidence_items = relationship("EvidenceVaultItem", back_populates="incident", cascade="all, delete-orphan")


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    sender = Column(String(128), default="Suspect")
    timestamp = Column(DateTime, nullable=True)
    content = Column(Text, nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    threat_score = Column(Float, default=0.0)
    is_off_hours = Column(Boolean, default=False)
    evaluation_json = Column(Text, nullable=True)

    incident = relationship("Incident", back_populates="messages")


class ForensicTrace(Base):
    __tablename__ = "forensic_traces"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    raw_headers = Column(Text, nullable=False)
    originating_ip = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    spf_status = Column(String(32), default="Unknown")
    dkim_status = Column(String(32), default="None")
    hop_count = Column(Integer, default=0)
    parsed_hops_json = Column(Text, nullable=True)
    sha256_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=utcnow)

    incident = relationship("Incident", back_populates="forensic_traces")


class EvidenceVaultItem(Base):
    __tablename__ = "evidence_vault_items"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    item_type = Column(String(64), nullable=False)
    source = Column(String(128), default="User Ingestion")
    preview = Column(Text, nullable=True)
    sha256_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=utcnow)
    verified = Column(Boolean, default=True)

    incident = relationship("Incident", back_populates="evidence_items")
