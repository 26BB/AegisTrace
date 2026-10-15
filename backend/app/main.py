from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api import benchmark, forensics, incident
from backend.app.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database tables on startup
    init_db()
    yield


app = FastAPI(
    title="AegisTrace: Cyberstalking Detection & Forensic Incident Analysis Platform",
    description=(
        "Production-grade cybersecurity API for automated cyberstalking pattern recognition, "
        "temporal cadence analysis, RFC 822 email header routing forensics, "
        "SHA-256 evidence chain of custody, and statutory benchmark correlation."
    ),
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for Streamlit and external frontend consumers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(incident.router)
app.include_router(forensics.router)
app.include_router(benchmark.router)


@app.get("/", tags=["System Health"])
def root():
    return {
        "platform": "AegisTrace Forensic Incident Analysis System",
        "status": "ONLINE",
        "version": "1.0.0",
        "capabilities": [
            "Lexical Threat & Typology Scoring (Offline Heuristics)",
            "Temporal Cadence & Nocturnal Burst Analysis",
            "RFC 822 / 5322 Email Header Hop Forensics & Public IP Isolation",
            "ISO/IEC 27037 Cryptographic Evidence Chain-of-Custody (SHA-256)",
            "1999 DOJ Report & Modern Statutory Benchmark (BNS 78, IT Act, 18 USC 2261A)",
            "ReportLab Court-Admissible Forensic PDF Dossier Generation"
        ]
    }
