from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class MessageInput(BaseModel):
    content: str = Field(..., description="Raw text of the cyberstalking message")
    timestamp: Optional[str] = Field(None, description="ISO-8601 or standard datetime string of message")
    sender: Optional[str] = Field("Suspect", description="Sender handle or identifier")


class IncidentAnalyzeRequest(BaseModel):
    case_number: Optional[str] = Field(None, description="Optional custom case reference number")
    title: str = Field("Cyberstalking Incident Investigation", description="Title of the incident")
    victim_alias: Optional[str] = Field("Victim-Anonymous", description="Victim pseudonym or handle")
    suspect_alias: Optional[str] = Field("Unknown Suspect", description="Suspect pseudonym or handle")
    platform: Optional[str] = Field("Multi-Channel", description="Primary communication channel")
    messages: List[MessageInput] = Field(..., description="Sequential stream of suspected messages")
    raw_headers: Optional[str] = Field(None, description="Optional raw RFC 822 email headers")


class MessageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    sender: str
    timestamp: Optional[datetime] = None
    content: str
    sha256_hash: str
    threat_score: float
    is_off_hours: bool
    evaluation: Optional[Dict[str, Any]] = None


class ForensicTraceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    originating_ip: Optional[str] = None
    user_agent: Optional[str] = None
    spf_status: str
    dkim_status: str
    hop_count: int
    parsed_hops: List[Dict[str, Any]] = []
    sha256_hash: str
    created_at: Optional[datetime] = None


class HeaderParseRequest(BaseModel):
    raw_headers: str = Field(..., description="Raw RFC 822 email headers text")
    incident_id: Optional[int] = Field(None, description="Optional incident ID to associate with")


class HeaderParseResponse(BaseModel):
    success: bool
    subject: str
    date: str
    from_header: str
    to_header: str
    message_id: str
    originating_public_ip: str
    user_agent: str
    authentication: Dict[str, Any]
    hop_count: int
    hops: List[Dict[str, Any]]
    anomalies: List[str]
    sha256_hash: str
    summary: str


class BenchmarkMatchRequest(BaseModel):
    typologies: List[str] = Field(..., description="List of detected stalking typologies")
    threat_score: float = Field(..., description="Composite threat level score 0-100")
    off_hours_ratio: Optional[float] = Field(0.0, description="Ratio of messages between 11 PM - 5 AM")
    burst_count: Optional[int] = Field(0, description="Count of rapid message bursts")


class IncidentSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_number: str
    title: str
    victim_alias: str
    suspect_alias: str
    platform: str
    threat_score: float
    risk_tier: str
    created_at: datetime
    message_count: int


class IncidentDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_number: str
    title: str
    victim_alias: str
    suspect_alias: str
    platform: str
    threat_score: float
    risk_tier: str
    summary: Optional[str] = None
    analysis: Dict[str, Any]
    created_at: datetime
    messages: List[MessageResponse]
    forensic_trace: Optional[Dict[str, Any]] = None
