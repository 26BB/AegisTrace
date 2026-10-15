from fastapi import APIRouter
from backend.app.core.benchmark import LegalBenchmarkEngine
from backend.app.schemas import BenchmarkMatchRequest

router = APIRouter(prefix="/api/benchmark", tags=["Legal & Historical Benchmark"])


@router.get("/taxonomy")
def get_benchmark_taxonomy():
    """
    Returns the comprehensive cyberstalking legal taxonomy,
    including 1999 DOJ findings, modern statutory definitions (BNS 78, IT Act, 18 USC 2261A),
    and the technological evolutionary matrix.
    """
    return {
        "doj_1999_reference": LegalBenchmarkEngine.DOJ_1999_REFERENCE,
        "statutory_database": LegalBenchmarkEngine.STATUTORY_DATABASE,
        "evolutionary_matrix": LegalBenchmarkEngine.EVOLUTIONARY_MATRIX
    }


@router.post("/match")
def match_benchmark_elements(payload: BenchmarkMatchRequest):
    """
    Correlates detected cyberstalking typologies against 1999 DOJ benchmarks
    and evaluates element-by-element satisfaction for modern statutory penalties.
    """
    matched = LegalBenchmarkEngine.match_incident(
        detected_typologies=payload.typologies,
        threat_score=payload.threat_score,
        off_hours_ratio=payload.off_hours_ratio or 0.0,
        burst_count=payload.burst_count or 0
    )
    return matched
