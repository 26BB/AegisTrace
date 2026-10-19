import json
import os
import pytest
from datetime import datetime
from fastapi.testclient import TestClient

from backend.app.core.benchmark import LegalBenchmarkEngine
from backend.app.core.cadence_analyzer import CadenceAnalyzer
from backend.app.core.detector import StalkingDetector
from backend.app.core.evidence_vault import EvidenceVault
from backend.app.core.forensics_parser import ForensicHeaderParser
from backend.app.core.pdf_builder import ForensicPdfBuilder
from backend.app.database import SessionLocal, init_db
from backend.app.main import app
from backend.app.models import EvidenceVaultItem, ForensicTrace, Incident, Message


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    init_db()


@pytest.fixture
def sample_data():
    sample_path = os.path.join(os.path.dirname(__file__), "..", "data", "sample_incident.json")
    with open(sample_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def client():
    return TestClient(app)


# =============================================================================
# 1. EVIDENCE VAULT & CRYPTOGRAPHY TESTS
# =============================================================================
class TestEvidenceVault:
    def test_sha256_reproducibility(self):
        text = "I know where you live"
        h1 = EvidenceVault.calculate_sha256(text)
        h2 = EvidenceVault.calculate_sha256(text)
        assert len(h1) == 64
        assert h1 == h2

    def test_canonical_json_hashing(self):
        dict1 = {"b": 2, "a": 1}
        dict2 = {"a": 1, "b": 2}
        assert EvidenceVault.calculate_sha256(dict1) == EvidenceVault.calculate_sha256(dict2)

    def test_custody_record_and_tamper_verification(self):
        content = "Threat message payload"
        rec = EvidenceVault.generate_custody_record("EV-001", "MESSAGE", content, "Suspect")
        assert rec["evidence_id"] == "EV-001"
        assert rec["verified"] is True

        # Intact verification
        verify_ok = EvidenceVault.verify_tamper_integrity(rec["sha256_hash"], content)
        assert verify_ok["is_valid"] is True
        assert verify_ok["status"] == "VERIFIED_INTACT"

        # Tampered verification
        verify_fail = EvidenceVault.verify_tamper_integrity(rec["sha256_hash"], "Altered content")
        assert verify_fail["is_valid"] is False
        assert verify_fail["status"] == "TAMPER_DETECTED"


# =============================================================================
# 2. DETECTOR & HEURISTIC TYPOLOGY TESTS
# =============================================================================
class TestStalkingDetector:
    def test_persistent_pursuit(self):
        msg = "Why did you block me? Unblock me now and reply to me, stop ignoring!"
        res = StalkingDetector.analyze_message(msg)
        assert res["typologies"]["persistent_pursuit"]["active"] is True
        assert res["typologies"]["persistent_pursuit"]["score"] >= 50.0

    def test_explicit_threats_and_urgency(self):
        msg = "I WILL DESTROY YOU AND RUIN YOUR LIFE! LAST CHANCE OR YOU WILL REGRET THIS!"
        res = StalkingDetector.analyze_message(msg)
        assert res["typologies"]["threats_intimidation"]["active"] is True
        assert res["risk_tier"] in ["HIGH", "CRITICAL"]
        assert res["intensity_metrics"]["caps_ratio"] > 0.5

    def test_surveillance_and_doxxing_entities(self):
        msg = "I know where you live at 742 Evergreen Terrace Apt 4B. Saw you today outside your house. Call +1-555-019-2834."
        res = StalkingDetector.analyze_message(msg)
        assert res["typologies"]["surveillance_monitoring"]["active"] is True
        assert res["typologies"]["doxxing_impersonation"]["active"] is True
        assert len(res["entities_detected"].get("phones", [])) >= 1
        assert len(res["entities_detected"].get("residential_clues", [])) >= 1

    def test_benign_message(self):
        msg = "Hello, could you please send the quarterly finance spreadsheet when you get a chance?"
        res = StalkingDetector.analyze_message(msg)
        assert res["threat_score"] == 0.0
        assert res["risk_tier"] == "LOW"


# =============================================================================
# 3. CADENCE & TEMPORAL TESTS
# =============================================================================
class TestCadenceAnalyzer:
    def test_off_hours_nocturnal_detection(self):
        dt_night = datetime(2026, 10, 14, 23, 45, 0)
        dt_early = datetime(2026, 10, 14, 2, 30, 0)
        dt_day = datetime(2026, 10, 14, 14, 0, 0)

        assert CadenceAnalyzer.is_off_hours(dt_night) is True
        assert CadenceAnalyzer.is_off_hours(dt_early) is True
        assert CadenceAnalyzer.is_off_hours(dt_day) is False

    def test_burst_and_acceleration_detection(self):
        messages = [
            {"timestamp": "2026-10-14T10:00:00Z", "content": "Msg 1"},
            {"timestamp": "2026-10-14T14:00:00Z", "content": "Msg 2"},  # 4 hours
            {"timestamp": "2026-10-14T18:00:00Z", "content": "Msg 3"},  # 4 hours
            {"timestamp": "2026-10-14T23:30:00Z", "content": "Msg 4"},  # nocturnal
            {"timestamp": "2026-10-14T23:32:00Z", "content": "Msg 5"},  # 2 min burst
            {"timestamp": "2026-10-14T23:34:00Z", "content": "Msg 6"},  # 2 min burst
        ]
        cad = CadenceAnalyzer.analyze_cadence(messages)
        assert cad["burst_clusters_count"] >= 2
        assert cad["off_hours_ratio"] > 0.4
        assert cad["escalation_detected"] is True
        assert cad["acceleration_factor"] > 1.5


# =============================================================================
# 4. FORENSIC HEADER PARSER TESTS
# =============================================================================
class TestForensicHeaderParser:
    def test_ip_public_vs_private_classification(self):
        # Private LAN
        assert ForensicHeaderParser.is_public_ip("192.168.1.1") is False
        assert ForensicHeaderParser.is_public_ip("10.0.0.1") is False
        assert ForensicHeaderParser.is_public_ip("172.16.5.10") is False
        assert ForensicHeaderParser.is_public_ip("127.0.0.1") is False

        # Public WAN
        assert ForensicHeaderParser.is_public_ip("185.220.101.5") is True
        assert ForensicHeaderParser.is_public_ip("203.0.113.194") is True
        assert ForensicHeaderParser.is_public_ip("8.8.8.8") is True

    def test_header_route_and_originating_ip(self, sample_data):
        raw_headers = sample_data["raw_email_headers"]
        res = ForensicHeaderParser.parse_headers(raw_headers)
        assert res["success"] is True
        assert res["originating_public_ip"] == "203.0.113.194"
        assert res["hop_count"] == 5
        assert res["authentication"]["spf_status"] in ["FAIL", "SOFTFAIL"]
        assert "Thunderbird" in res["user_agent"] or "Mozilla" in res["user_agent"]


# =============================================================================
# 5. BENCHMARK & STATUTORY TESTS
# =============================================================================
class TestLegalBenchmarkEngine:
    def test_statutory_mapping(self):
        typologies = ["Persistent Pursuit", "Threats & Intimidation", "Surveillance & Monitoring", "Doxxing & Impersonation"]
        res = LegalBenchmarkEngine.match_incident(typologies, threat_score=95.0, off_hours_ratio=0.7)

        statute_codes = [s["code"] for s in res["applicable_statutes"]]
        assert "BNS_78" in statute_codes
        assert "IT_ACT_66E" in statute_codes
        assert "US_CODE_2261A" in statute_codes
        assert len(res["doj_corroborations"]) >= 1
        assert len(res["preservation_recommendations"]) >= 1


# =============================================================================
# 6. PDF DOSSIER BUILDER TESTS
# =============================================================================
class TestPdfBuilder:
    def test_pdf_generation(self, sample_data):
        detection = StalkingDetector.analyze_stream(sample_data["messages"])
        trace = ForensicHeaderParser.parse_headers(sample_data["raw_email_headers"])
        benchmark = LegalBenchmarkEngine.match_incident(detection["typologies_detected"], 90.0)

        pdf_bytes = ForensicPdfBuilder.generate_dossier(
            incident_data=sample_data["incident_metadata"],
            analysis_data=detection,
            forensic_trace=trace,
            legal_benchmark=benchmark
        )
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 2000
        # Verify PDF magic bytes '%PDF-'
        assert pdf_bytes.startswith(b"%PDF-")


# =============================================================================
# 7. FASTAPI INTEGRATION & DATABASE PERSISTENCE TESTS
# =============================================================================
class TestFastAPIIntegration:
    def test_root_health(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert r.json()["status"] == "ONLINE"

    def test_benchmark_taxonomy(self, client):
        r = client.get("/api/benchmark/taxonomy")
        assert r.status_code == 200
        data = r.json()
        assert "doj_1999_reference" in data
        assert "statutory_database" in data
        assert "evolutionary_matrix" in data

    def test_header_parse_endpoint(self, client, sample_data):
        r = client.post("/api/forensics/parse-header", json={"raw_headers": sample_data["raw_email_headers"]})
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        assert data["originating_public_ip"] == "203.0.113.194"
        assert len(data["sha256_hash"]) == 64

    def test_incident_analyze_persist_and_retrieve(self, client, sample_data):
        import uuid
        test_case_num = f"AEGIS-TEST-{uuid.uuid4().hex[:8]}"
        payload = {
            "case_number": test_case_num,
            "title": sample_data["incident_metadata"]["title"],
            "victim_alias": sample_data["incident_metadata"]["victim_alias"],
            "suspect_alias": sample_data["incident_metadata"]["suspect_alias"],
            "platform": sample_data["incident_metadata"]["platform"],
            "messages": sample_data["messages"],
            "raw_headers": sample_data["raw_email_headers"]
        }
        # Ingestion & Analysis
        r_post = client.post("/api/incidents/analyze", json=payload)
        assert r_post.status_code == 200
        data_post = r_post.json()
        assert data_post["threat_score"] >= 80.0
        assert data_post["risk_tier"] == "CRITICAL"
        inc_id = data_post["incident_id"]

        # Detail Retrieval
        r_get = client.get(f"/api/incidents/{inc_id}")
        assert r_get.status_code == 200
        data_get = r_get.json()
        assert data_get["case_number"] == test_case_num
        assert len(data_get["messages"]) == len(sample_data["messages"])
        assert data_get["forensic_trace"]["originating_public_ip"] == "203.0.113.194"

        # PDF Dossier Download from Endpoint
        r_pdf = client.get(f"/api/incidents/{inc_id}/pdf")
        assert r_pdf.status_code == 200
        assert r_pdf.headers["content-type"] == "application/pdf"
        assert r_pdf.content.startswith(b"%PDF-")

    def test_direct_pdf_generation_endpoint(self, client, sample_data):
        detection = StalkingDetector.analyze_stream(sample_data["messages"])
        trace = ForensicHeaderParser.parse_headers(sample_data["raw_email_headers"])
        direct_payload = {
            "incident": sample_data["incident_metadata"],
            "analysis": detection,
            "forensic_trace": trace,
            "legal_benchmark": LegalBenchmarkEngine.match_incident(detection["typologies_detected"], 95.0)
        }
        r = client.post("/api/incidents/generate-pdf-direct", json=direct_payload)
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/pdf"
        assert len(r.content) > 3000
