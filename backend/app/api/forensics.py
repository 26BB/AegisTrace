import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.evidence_vault import EvidenceVault
from backend.app.core.forensics_parser import ForensicHeaderParser
from backend.app.database import get_db
from backend.app.models import ForensicTrace, Incident
from backend.app.schemas import HeaderParseRequest, HeaderParseResponse

router = APIRouter(prefix="/api/forensics", tags=["Digital Forensics"])


@router.post("/parse-header", response_model=HeaderParseResponse)
def parse_email_header(payload: HeaderParseRequest, db: Session = Depends(get_db)):
    """
    Parses raw RFC 822 / RFC 5322 email headers, extracts routing hops,
    filters private IPs, pinpoints the originating public IP, and seals evidence with SHA-256.
    """
    if not payload.raw_headers.strip():
        raise HTTPException(status_code=400, detail="Header content cannot be empty.")

    parsed = ForensicHeaderParser.parse_headers(payload.raw_headers)
    if not parsed.get("success"):
        raise HTTPException(status_code=422, detail=parsed.get("error", "Failed to parse RFC 822 headers."))

    header_hash = EvidenceVault.calculate_sha256(payload.raw_headers)

    # If associated with an existing incident in DB, record forensic trace
    if payload.incident_id:
        incident = db.query(Incident).filter(Incident.id == payload.incident_id).first()
        if incident:
            trace_record = ForensicTrace(
                incident_id=incident.id,
                raw_headers=payload.raw_headers,
                originating_ip=parsed.get("originating_public_ip"),
                user_agent=parsed.get("user_agent"),
                spf_status=parsed.get("authentication", {}).get("spf_status", "Unknown"),
                dkim_status=parsed.get("authentication", {}).get("dkim_status", "None"),
                hop_count=parsed.get("hop_count", 0),
                parsed_hops_json=json.dumps(parsed.get("hops", [])),
                sha256_hash=header_hash
            )
            db.add(trace_record)
            db.commit()

    return HeaderParseResponse(
        success=True,
        subject=parsed.get("subject", "N/A"),
        date=parsed.get("date", "N/A"),
        from_header=parsed.get("from", "N/A"),
        to_header=parsed.get("to", "N/A"),
        message_id=parsed.get("message_id", "N/A"),
        originating_public_ip=parsed.get("originating_public_ip", "Unknown"),
        user_agent=parsed.get("user_agent", "Unknown"),
        authentication=parsed.get("authentication", {}),
        hop_count=parsed.get("hop_count", 0),
        hops=parsed.get("hops", []),
        anomalies=parsed.get("anomalies", []),
        sha256_hash=header_hash,
        summary=parsed.get("summary", "")
    )
