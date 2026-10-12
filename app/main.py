import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

# Ensure project root is on sys.path when running app/main.py directly
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.analyzers.ai_reasoning import generate_ai_threat_report
from app.analyzers.brand_analyzer import analyze_brand_impersonation
from app.analyzers.lexical_analyzer import analyze_lexical
from app.analyzers.ml_classifier import ml_classifier
from app.analyzers.network_inspector import analyze_network
from app.database import (
    clear_history,
    get_recent_scans,
    get_scan_by_id,
    get_stats,
    init_db,
    save_scan,
)
from app.models import (
    AnalyzeRequest,
    BulkAnalyzeRequest,
    DomainAnalysisResponse,
)

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="PhishGuard AI — Hybrid Phishing Domain Analysis Platform",
    description="Deep domain & URL threat intelligence engine combining Lexical Heuristics, Brand/Homoglyph Detection, Live DNS/SSL/WHOIS Inspection, Random Forest ML, and AI Threat Reasoning.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def compute_overall_score_and_verdict(
    lexical_score: int,
    brand_score: int,
    network_score: int,
    ml_score: int,
    is_official: bool,
    has_redirect_trick: bool,
    network_scanned: bool,
) -> Tuple[int, str, str]:
    if is_official and not has_redirect_trick:
        overall = min(8, max(2, int(network_score * 0.1)))
        return overall, "SAFE", "LIKELY SAFE"

    if network_scanned:
        weighted = (
            (ml_score * 0.38)
            + (lexical_score * 0.25)
            + (brand_score * 0.22)
            + (network_score * 0.15)
        )
    else:
        weighted = (
            (ml_score * 0.45)
            + (lexical_score * 0.30)
            + (brand_score * 0.25)
        )

    # Boost floor when strong brand impersonation or homoglyph attack is present
    if brand_score >= 60 and lexical_score >= 20:
        weighted = max(weighted, 82.0 + min(16.0, (lexical_score + network_score) * 0.18))
    elif brand_score >= 55:
        weighted = max(weighted, 74.0)
    elif lexical_score >= 65 and ml_score >= 70:
        weighted = max(weighted, 76.0)

    overall = int(min(100, max(0, round(weighted))))

    if overall >= 80:
        risk_level = "CRITICAL"
        verdict = "PHISHING / MALICIOUS"
    elif overall >= 65:
        risk_level = "HIGH"
        verdict = "PHISHING / MALICIOUS"
    elif overall >= 40:
        risk_level = "MEDIUM"
        verdict = "SUSPICIOUS"
    elif overall >= 20:
        risk_level = "LOW"
        verdict = "LIKELY SAFE"
    else:
        risk_level = "SAFE"
        verdict = "LIKELY SAFE"

    return overall, risk_level, verdict


def run_domain_analysis(target: str, deep_network_scan: bool = True, persist: bool = True) -> DomainAnalysisResponse:
    start_time = time.perf_counter()
    cleaned_target = target.strip()
    if not cleaned_target or len(cleaned_target) < 3:
        raise ValueError("Please provide a valid domain name or URL to analyze.")

    lexical = analyze_lexical(cleaned_target)
    brand = analyze_brand_impersonation(lexical.domain, lexical.registered_domain, lexical.tld)
    network = analyze_network(lexical.domain, lexical.registered_domain, perform_scan=deep_network_scan)
    ml_pred = ml_classifier.predict(lexical, brand, network)

    has_trick = lexical.has_at_symbol or lexical.has_double_slash_redirect or lexical.has_ip_address
    overall_score, risk_level, verdict = compute_overall_score_and_verdict(
        lexical_score=lexical.lexical_risk_score,
        brand_score=brand.brand_risk_score,
        network_score=network.network_risk_score,
        ml_score=ml_pred.ml_risk_score,
        is_official=brand.is_official_brand_domain,
        has_redirect_trick=has_trick,
        network_scanned=network.scanned,
    )

    ai_report = generate_ai_threat_report(
        overall_score=overall_score,
        risk_level=risk_level,
        lexical=lexical,
        brand=brand,
        network=network,
        ml_res=ml_pred,
    )

    duration_ms = int((time.perf_counter() - start_time) * 1000)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    response = DomainAnalysisResponse(
        timestamp=now_iso,
        input_target=cleaned_target,
        normalized_domain=lexical.domain,
        overall_risk_score=overall_score,
        risk_level=risk_level,
        verdict=verdict,
        lexical=lexical,
        brand=brand,
        network=network,
        ml_prediction=ml_pred,
        ai_report=ai_report,
        scan_duration_ms=duration_ms,
    )

    if persist:
        scan_id = save_scan(response)
        response.scan_id = scan_id

    return response


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.post("/api/analyze", response_model=DomainAnalysisResponse)
async def analyze_endpoint(req: AnalyzeRequest):
    try:
        return run_domain_analysis(req.target, deep_network_scan=req.deep_network_scan, persist=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/bulk-analyze")
async def bulk_analyze_endpoint(req: BulkAnalyzeRequest):
    results = []
    for raw_item in req.targets[:50]:
        item = raw_item.strip()
        if not item:
            continue
        try:
            res = run_domain_analysis(item, deep_network_scan=req.deep_network_scan, persist=True)
            results.append(res)
        except Exception as exc:
            results.append({"input_target": item, "error": str(exc)})
    return {"count": len(results), "results": results, "stats": get_stats()}


@app.get("/api/history")
async def history_endpoint(limit: int = 20):
    return {
        "stats": get_stats(),
        "recent_scans": get_recent_scans(limit=limit),
    }


@app.get("/api/history/{scan_id}")
async def history_detail_endpoint(scan_id: int):
    record = get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")
    return record


@app.delete("/api/history")
async def clear_history_endpoint():
    clear_history()
    return {"status": "cleared", "stats": get_stats()}


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "service": "PhishGuard AI", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)

