# AegisTrace: Cyberstalking Detection & Forensic Incident Analysis Platform

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32%2B-FF4B4B.svg)](https://streamlit.io/)
[![ReportLab](https://img.shields.io/badge/ReportLab-4.1%2B-darkred.svg)](https://www.reportlab.com/)
[![Evidence Admissibility](https://img.shields.io/badge/Forensics-ISO%2FIEC%2027037-navy.svg)](#)

**AegisTrace** is a digital forensic incident investigation and cyberstalking threat detection platform designed for law enforcement analysts, incident response teams, and digital evidence examiners. It automates linguistic threat scoring, nocturnal cadence escalation analysis, RFC 822 email header hop routing, cryptographic chain-of-custody sealing (SHA-256), and statutory cross-referencing against the landmark **1999 US DOJ Cyberstalking Report** and modern legal frameworks (**Bharatiya Nyaya Sanhita BNS Sec. 78**, **Indian IT Act 66E/67**, and **18 U.S.C. § 2261A**).

---

## 🏛️ Platform Architecture

```
AegisTrace: Cyberstalking Detection & Forensic Incident Analysis Platform
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                     # FastAPI server & CORS middleware
│   │   ├── database.py                 # SQLAlchemy SQLite engine & session factory
│   │   ├── models.py                   # ORM models (Incident, Message, ForensicTrace, EvidenceVaultItem)
│   │   ├── schemas.py                  # Pydantic v2 schemas
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── incident.py             # Incident ingestion, threat scoring, and PDF generation
│   │   │   ├── forensics.py            # RFC 822 email header routing trace & IP extraction
│   │   │   └── benchmark.py            # DOJ 1999 & statutory taxonomy endpoints
│   │   └── core/
│   │       ├── __init__.py
│   │       ├── detector.py             # Heuristic threat scoring (0-100) & typology mapping
│   │       ├── cadence_analyzer.py     # Time delta calculation, off-hours (11 PM - 5 AM) & bursts
│   │       ├── forensics_parser.py     # RFC 822 hop tracing, private IP filtration, originating IP
│   │       ├── evidence_vault.py       # SHA-256 cryptographic chain of custody & tamper check
│   │       ├── benchmark.py            # 1999 DOJ vs modern legal benchmark (BNS 78, IT Act, 18 USC 2261A)
│   │       └── pdf_builder.py          # ReportLab court-admissible multi-page PDF dossier generator
├── dashboard.py                        # Streamlit dark-themed cybersecurity interface (3 tabs)
├── data/
│   └── sample_incident.json            # Realistic multi-message stalking escalation scenario & email headers
├── requirements.txt                    # Project dependencies
├── run.py                              # Service orchestrator (Backend + Dashboard)
└── README.md                           # Documentation & architecture specifications
```

---

## 🔍 Core Engines & Forensic Modules

### 1. `backend/app/core/detector.py` (Offline Threat & Typology Engine)
- **Zero API Dependency:** Runs offline with zero external API key requirements using lexical heuristics, regex patterns, and linguistic metrics.
- **Threat Level Scoring (0–100):** Evaluates composite severity based on threat keywords, PII entities, sentiment intensity, all-caps ratios, and urgency indicators.
- **Typology Classification:**
  - `Persistent Pursuit`: Repetitive unreciprocated outreach, multiple account creation, block bypassing.
  - `Threats & Intimidation`: Physical harm, extortion, blackmail, suicidal coercion, destruction.
  - `Surveillance & Monitoring`: Physical tracking, observation of habits, schedule reconnaissance, spy references.
  - `Doxxing & Impersonation`: Leaking residential address, phone numbers, employer details, or malicious impersonation.

### 2. `backend/app/core/cadence_analyzer.py` (Temporal Cadence & Nocturnal Velocity)
- **Time Delta Intervals:** Computes statistical mean, median, min, max, and standard deviation between sequential transmissions.
- **Off-Hours Concentration:** Isolates messages transmitted during nocturnal hours (**11:00 PM – 5:00 AM**) to quantify obsessive temporal disruption.
- **Velocity Burst Clusters:** Flags clusters of rapid-fire messages (< 5-minute and < 15-minute intervals).
- **Cadence Acceleration:** Computes the interval shrinkage factor between early and late stages of an incident to detect imminent crisis escalation.

### 3. `backend/app/core/forensics_parser.py` (RFC 822/5322 Email Routing Forensics)
- **Hop Sequence Reconstruction:** Reconstructs the chronological MTA relay path from originating client to destination server.
- **RFC 1918 Bogon Filtration:** Filters out private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`) to isolate the true public originating IP.
- **Authentication & Integrity Analysis:** Parses SPF records (`PASS`, `FAIL`, `SOFTFAIL`), DKIM cryptographic signatures, and DMARC alignments.
- **Client Footprint:** Extracts `User-Agent`, `X-Mailer`, and explicit `X-Originating-IP` headers.

### 4. `backend/app/core/evidence_vault.py` (Cryptographic Chain of Custody)
- **SHA-256 Hashing:** Computes cryptographic digests for raw message text, timestamp tuples, raw headers, and audit summaries.
- **ISO/IEC 27037 Compliance:** Generates admissible digital custody receipts containing custodian ID, acquisition timestamp in UTC, and tamper verification status.

### 5. `backend/app/core/benchmark.py` (DOJ 1999 vs Modern Jurisprudence)
- **1999 DOJ Report Corroboration:** Cross-references patterns against the landmark US Department of Justice report *"Cyberstalking: A New Challenge for Law Enforcement and Industry"*.
- **Modern Criminal Statutes:**
  - **BNS Section 78** (Bharatiya Nyaya Sanhita, 2023 - Stalking, successor to IPC 354D).
  - **IT Act, 2000**: Section 66E (Privacy Violation), Section 66D (Cheating by Personation), Section 67 (Obscenity).
  - **18 U.S. Code § 2261A**: Federal Interstate Cyberstalking statute.
- **Elements of Crime Checklist:** Evaluates whether observed facts satisfy each statutory requirement for prosecution.

### 6. `backend/app/core/pdf_builder.py` (ReportLab Forensic Dossier)
- Multi-page court-admissible PDF generator with custom `NumberedCanvas` ("Page X of Y").
- Complete with Case Particulars, Executive Risk Gauge, Typology Breakdown, Temporal Metrics, Evidence Ledger, Header Hop Table, Statutory Mappings, and Digital Forensic Verification Seal.

---

## 🖥️ Streamlit Cybersecurity Dashboard (`dashboard.py`)

A high-tech dark interface (`#0b0f19`) featuring:
1. **Tab 1: "Analyze Incident"**
   - Stream editor for multi-message streams with timestamps and sender identifiers.
   - One-click **"Reload Realistic Incident Scenario"** from `data/sample_incident.json`.
   - Real-time threat gauge (0-100) and risk tier badge (`LOW`, `ELEVATED`, `HIGH`, `CRITICAL`).
   - Typology breakdown cards with active trigger highlighting.
   - Interactive timeline chart mapping threat escalation and cadence.
   - ISO/IEC 27037 Cryptographic Evidence Ledger with SHA-256 hashes.
2. **Tab 2: "Forensic Header Trace"**
   - RFC 822 raw email header parser.
   - True public originating IP extraction card.
   - Chronological MTA hop sequence table (From Host, By Host, IP, Hop Type).
   - SPF, DKIM, and spoofing anomaly indicators.
3. **Tab 3: "DOJ 1999 vs Modern Benchmark & Dossier"**
   - Comparative 1999 vs 2026 technological evolution matrix.
   - Dynamic statutory mapping cards (BNS 78, IT Act, 18 U.S.C. 2261A).
   - Instant download button for the official **ReportLab PDF Incident Dossier**.

---

## 🚀 Quick Start Guide

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch Backend & Dashboard
You can run both concurrently using the `run.py` orchestrator:
```bash
python run.py
```
Or launch them independently:
```bash
# Terminal 1: FastAPI Backend
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Streamlit Dashboard
streamlit run dashboard.py --server.port 8501
```

Access the interfaces:
- **Streamlit Dashboard:** `http://localhost:8501`
- **FastAPI Interactive Swagger Docs:** `http://127.0.0.1:8000/docs`
- **FastAPI ReDoc:** `http://127.0.0.1:8000/redoc`

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/incidents/analyze` | Ingests message stream + headers, performs full analysis, stores in SQLite, and returns threat evaluation. |
| `GET` | `/api/incidents` | Lists all analyzed incidents with threat level summaries. |
| `GET` | `/api/incidents/{id}` | Retrieves full incident record, individual evaluations, and evidence ledger. |
| `GET` | `/api/incidents/{id}/pdf` | Generates and downloads the official court-admissible PDF dossier. |
| `POST` | `/api/incidents/generate-pdf-direct` | One-shot direct PDF dossier generation from raw payload. |
| `POST` | `/api/forensics/parse-header` | Parses RFC 822 raw email headers, isolates public originating IP, and seals with SHA-256. |
| `GET` | `/api/benchmark/taxonomy` | Returns DOJ 1999 reference, modern statutory definitions, and evolutionary matrix. |
| `POST` | `/api/benchmark/match` | Matches detected typologies against criminal statutes. |

---

## ⚖️ Evidentiary Admissibility Notice
AegisTrace produces digital forensics documentation structured for criminal proceedings and civil restraining order hearings under **Indian Evidence Act / BSA (Bharatiya Sakshya Adhiniyam Sec. 63)** electronic record admissibility guidelines and **US Federal Rules of Evidence Rule 902(13)/(14)** (certified records generated by electronic processes).
