import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from backend.app.core.benchmark import LegalBenchmarkEngine
from backend.app.core.cadence_analyzer import CadenceAnalyzer
from backend.app.core.detector import StalkingDetector
from backend.app.core.evidence_vault import EvidenceVault
from backend.app.core.forensics_parser import ForensicHeaderParser
from backend.app.core.pdf_builder import ForensicPdfBuilder
from backend.app.database import get_db
from backend.app.models import EvidenceVaultItem, ForensicTrace, Incident, Message
from backend.app.schemas import (
    IncidentAnalyzeRequest,
    IncidentDetailResponse,
    IncidentSummaryResponse,
    MessageResponse,
)

router = APIRouter(prefix="/api/incidents", tags=["Incidents & Threat Analysis"])


@router.post("/analyze")
def analyze_incident(payload: IncidentAnalyzeRequest, db: Session = Depends(get_db)):
    """
    Ingests a sequence of messages, performs lexical threat analysis,
    calculates temporal cadence metrics, generates SHA-256 evidence seals,
    cross-references 1999 DOJ / modern statutory benchmarks, and persists to the database.
    """
    if not payload.messages:
        raise HTTPException(status_code=400, detail="Incident must contain at least one message.")

    # Generate Case Number if omitted
    case_number = payload.case_number or f"AEGIS-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    # 1. Lexical & Typological Threat Analysis
    raw_message_dicts = [
        {
            "id": idx + 1,
            "sender": m.sender or "Suspect",
            "timestamp": m.timestamp,
            "content": m.content
        }
        for idx, m in enumerate(payload.messages)
    ]
    detection_result = StalkingDetector.analyze_stream(raw_message_dicts)

    # 2. Temporal Cadence Analysis
    cadence_result = CadenceAnalyzer.analyze_cadence(raw_message_dicts)

    # 3. Composite Threat Level Calculation
    # Blends linguistic severity (75%) with temporal risk (25%)
    base_linguistic = detection_result["aggregate_threat_score"]
    temporal_risk = cadence_result["temporal_risk_score"]
    composite_threat = round(min(100.0, (base_linguistic * 0.75) + (temporal_risk * 0.25)), 1)

    if composite_threat >= 80.0:
        composite_tier = "CRITICAL"
    elif composite_threat >= 60.0:
        composite_tier = "HIGH"
    elif composite_threat >= 30.0:
        composite_tier = "ELEVATED"
    else:
        composite_tier = "LOW"

    # 4. Digital Evidence Cryptographic Sealing (SHA-256)
    evidence_ledger: List[Dict[str, Any]] = []
    for item in raw_message_dicts:
        msg_receipt = EvidenceVault.generate_custody_record(
            item_id=f"EV-MSG-{item['id']:03d}",
            item_type="MESSAGE_CONTENT",
            content=item["content"],
            source_identifier=f"{item['sender']} @ {item.get('timestamp', 'Unknown')}",
            recorded_by="AegisTrace-Forensic-Vault"
        )
        evidence_ledger.append(msg_receipt)

    # 5. Header Analysis if provided
    forensic_trace_data: Optional[Dict[str, Any]] = None
    if payload.raw_headers and payload.raw_headers.strip():
        parsed_hdr = ForensicHeaderParser.parse_headers(payload.raw_headers)
        if parsed_hdr.get("success"):
            forensic_trace_data = parsed_hdr
            hdr_receipt = EvidenceVault.generate_custody_record(
                item_id=f"EV-HDR-{uuid.uuid4().hex[:4].upper()}",
                item_type="RFC822_HEADER",
                content=payload.raw_headers,
                source_identifier=f"Subject: {parsed_hdr.get('subject')}",
                recorded_by="AegisTrace-Forensic-Vault"
            )
            evidence_ledger.append(hdr_receipt)

    # 6. Benchmark & Statutory Matching
    legal_benchmark = LegalBenchmarkEngine.match_incident(
        detected_typologies=detection_result["typologies_detected"],
        threat_score=composite_threat,
        off_hours_ratio=cadence_result["off_hours_ratio"],
        burst_count=cadence_result["burst_clusters_count"]
    )

    # 7. Dossier Audit Fingerprint
    dossier_snapshot = {
        "case_number": case_number,
        "threat_score": composite_threat,
        "risk_tier": composite_tier,
        "evidence_ledger": evidence_ledger
    }
    dossier_hash = EvidenceVault.calculate_sha256(dossier_snapshot)

    # Consolidated analysis payload
    analysis_payload = {
        "aggregate_threat_score": composite_threat,
        "risk_tier": composite_tier,
        "linguistic_threat_score": base_linguistic,
        "temporal_threat_score": temporal_risk,
        "message_count": len(payload.messages),
        "off_hours_ratio": cadence_result["off_hours_ratio"],
        "burst_clusters_count": cadence_result["burst_clusters_count"],
        "typologies_detected": detection_result["typologies_detected"],
        "typology_scores": detection_result["typology_scores"],
        "cumulative_triggers": detection_result["cumulative_triggers"],
        "cadence_metrics": cadence_result,
        "evidence_ledger": evidence_ledger,
        "legal_benchmark": legal_benchmark,
        "dossier_hash": dossier_hash
    }

    # Summary narrative
    summary_text = (
        f"Incident evaluated with composite threat score of {composite_threat}/100 ({composite_tier}). "
        f"Identified typologies: {', '.join(detection_result['typologies_detected']) or 'None'}. "
        f"{cadence_result['cadence_summary']}"
    )

    # 8. Persist to SQLite Database
    incident_record = Incident(
        case_number=case_number,
        title=payload.title,
        victim_alias=payload.victim_alias or "Victim-Anonymous",
        suspect_alias=payload.suspect_alias or "Unknown Suspect",
        platform=payload.platform or "Multi-Channel",
        threat_score=composite_threat,
        risk_tier=composite_tier,
        summary=summary_text,
        analysis_json=json.dumps(analysis_payload)
    )
    db.add(incident_record)
    db.flush()  # obtain incident_record.id

    # Add message records
    for idx, (m_input, m_eval, ledger_item) in enumerate(
        zip(payload.messages, detection_result["individual_evaluations"], evidence_ledger)
    ):
        dt = CadenceAnalyzer.parse_datetime(m_input.timestamp)
        is_off = CadenceAnalyzer.is_off_hours(dt) if dt else False
        msg_db = Message(
            incident_id=incident_record.id,
            sender=m_input.sender or "Suspect",
            timestamp=dt,
            content=m_input.content,
            sha256_hash=ledger_item["sha256_hash"],
            threat_score=m_eval["evaluation"]["threat_score"],
            is_off_hours=is_off,
            evaluation_json=json.dumps(m_eval["evaluation"])
        )
        db.add(msg_db)

    # Add forensic trace if available
    if forensic_trace_data:
        ft_record = ForensicTrace(
            incident_id=incident_record.id,
            raw_headers=payload.raw_headers,
            originating_ip=forensic_trace_data.get("originating_public_ip"),
            user_agent=forensic_trace_data.get("user_agent"),
            spf_status=forensic_trace_data.get("authentication", {}).get("spf_status", "Unknown"),
            dkim_status=forensic_trace_data.get("authentication", {}).get("dkim_status", "None"),
            hop_count=forensic_trace_data.get("hop_count", 0),
            parsed_hops_json=json.dumps(forensic_trace_data.get("hops", [])),
            sha256_hash=EvidenceVault.calculate_sha256(payload.raw_headers)
        )
        db.add(ft_record)

    # Add evidence vault ledger items
    for ev in evidence_ledger:
        ev_item = EvidenceVaultItem(
            incident_id=incident_record.id,
            item_type=ev["item_type"],
            source=ev["source"],
            preview=ev["preview"],
            sha256_hash=ev["sha256_hash"],
            verified=True
        )
        db.add(ev_item)

    db.commit()
    db.refresh(incident_record)

    return {
        "incident_id": incident_record.id,
        "case_number": incident_record.case_number,
        "threat_score": composite_threat,
        "risk_tier": composite_tier,
        "summary": summary_text,
        "analysis": analysis_payload,
        "forensic_trace": forensic_trace_data
    }


@router.get("", response_model=List[IncidentSummaryResponse])
def list_incidents(db: Session = Depends(get_db)):
    """
    Returns a listing of all analyzed cyberstalking incidents.
    """
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()
    results = []
    for inc in incidents:
        results.append(
            IncidentSummaryResponse(
                id=inc.id,
                case_number=inc.case_number,
                title=inc.title,
                victim_alias=inc.victim_alias,
                suspect_alias=inc.suspect_alias,
                platform=inc.platform,
                threat_score=inc.threat_score,
                risk_tier=inc.risk_tier,
                created_at=inc.created_at,
                message_count=len(inc.messages)
            )
        )
    return results


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    """
    Fetches comprehensive forensic analysis details for a single incident.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    analysis = json.loads(incident.analysis_json) if incident.analysis_json else {}

    messages_resp = []
    for m in incident.messages:
        messages_resp.append(
            MessageResponse(
                id=m.id,
                sender=m.sender,
                timestamp=m.timestamp,
                content=m.content,
                sha256_hash=m.sha256_hash,
                threat_score=m.threat_score,
                is_off_hours=m.is_off_hours,
                evaluation=json.loads(m.evaluation_json) if m.evaluation_json else None
            )
        )

    forensic_trace_dict = None
    if incident.forensic_traces:
        ft = incident.forensic_traces[0]
        forensic_trace_dict = {
            "originating_public_ip": ft.originating_ip,
            "user_agent": ft.user_agent,
            "authentication": {"spf_status": ft.spf_status, "dkim_status": ft.dkim_status},
            "hop_count": ft.hop_count,
            "hops": json.loads(ft.parsed_hops_json) if ft.parsed_hops_json else [],
            "sha256_hash": ft.sha256_hash
        }

    return IncidentDetailResponse(
        id=incident.id,
        case_number=incident.case_number,
        title=incident.title,
        victim_alias=incident.victim_alias,
        suspect_alias=incident.suspect_alias,
        platform=incident.platform,
        threat_score=incident.threat_score,
        risk_tier=incident.risk_tier,
        summary=incident.summary,
        analysis=analysis,
        created_at=incident.created_at,
        messages=messages_resp,
        forensic_trace=forensic_trace_dict
    )


@router.get("/{incident_id}/pdf")
def download_incident_pdf(incident_id: int, db: Session = Depends(get_db)):
    """
    Generates and downloads the official, court-admissible PDF incident dossier.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    analysis = json.loads(incident.analysis_json) if incident.analysis_json else {}

    forensic_trace_dict = None
    if incident.forensic_traces:
        ft = incident.forensic_traces[0]
        forensic_trace_dict = {
            "success": True,
            "originating_public_ip": ft.originating_ip,
            "user_agent": ft.user_agent,
            "authentication": {"spf_status": ft.spf_status, "dkim_status": ft.dkim_status},
            "hop_count": ft.hop_count,
            "hops": json.loads(ft.parsed_hops_json) if ft.parsed_hops_json else []
        }

    incident_dict = {
        "case_number": incident.case_number,
        "title": incident.title,
        "victim_alias": incident.victim_alias,
        "suspect_alias": incident.suspect_alias,
        "platform": incident.platform
    }

    pdf_bytes = ForensicPdfBuilder.generate_dossier(
        incident_data=incident_dict,
        analysis_data=analysis,
        forensic_trace=forensic_trace_dict,
        legal_benchmark=analysis.get("legal_benchmark")
    )

    filename = f"AegisTrace-Dossier-{incident.case_number}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.post("/generate-pdf-direct")
def generate_pdf_direct(payload: Dict[str, Any]):
    """
    One-shot direct PDF dossier generator from raw incident and analysis dicts.
    Useful for interactive dashboard exports before persisting.
    """
    incident_info = payload.get("incident", {})
    analysis_info = payload.get("analysis", {})
    trace_info = payload.get("forensic_trace")
    benchmark_info = payload.get("legal_benchmark") or analysis_info.get("legal_benchmark")

    pdf_bytes = ForensicPdfBuilder.generate_dossier(
        incident_data=incident_info,
        analysis_data=analysis_info,
        forensic_trace=trace_info,
        legal_benchmark=benchmark_info
    )

    case_ref = incident_info.get("case_number", "DIRECT-EXPORT")
    filename = f"AegisTrace-Dossier-{case_ref}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
