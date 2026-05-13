import os
from datetime import datetime, timezone
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from backend.models import EmailPayload, ScanResult
from backend.analyzers.headers import analyze_headers
from backend.analyzers.urls import analyze_urls
from backend.analyzers.content import analyze_content
from backend.analyzers.blocklist import check_blocklist, add_to_blocklist, remove_from_blocklist, get_blocklist
from backend.history import save_scan, load_history

load_dotenv()

app = FastAPI(title="Email Maliciousness Scorer")

# Allow requests from configured origins only.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv("ALLOWED_ORIGINS", "https://script.google.com,http://localhost:3000").split(",") if o.strip()],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)

VT_API_KEY = os.getenv("VT_API_KEY", "")
BACKEND_API_KEY = os.getenv("BACKEND_API_KEY", "")


def require_api_key(x_api_key: str | None):
    if not BACKEND_API_KEY:
        return
    if x_api_key != BACKEND_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")


def compute_verdict(score: int) -> str:
    if score >= 70:
        return "MALICIOUS"
    elif score >= 35:
        return "SUSPICIOUS"
    return "SAFE"


@app.post("/scan", response_model=ScanResult)
async def scan_email(payload: EmailPayload, x_api_key: str | None = Header(default=None)):
    """
    Main endpoint. Receives email data from the Gmail Add-on,
    runs all analyzers, and returns a scored result.
    """
    require_api_key(x_api_key)
    signals = []

    # 1. Blocklist check — if blocked, short-circuit immediately
    blocklist_signal = check_blocklist(payload.from_email)
    signals.append(blocklist_signal)

    if not blocklist_signal.passed:
        result = ScanResult(
            message_id=payload.message_id,
            from_email=payload.from_email,
            subject=payload.subject or "",
            total_score=100,
            verdict="MALICIOUS",
            signals=signals,
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )
        save_scan(result)
        return result

    # 2. Header authentication (SPF/DKIM/DMARC)
    header_signal = analyze_headers(payload.headers or {})
    signals.append(header_signal)

    # 3. URL reputation via VirusTotal
    if VT_API_KEY:
        url_signal = await analyze_urls(payload.urls or [], VT_API_KEY)
    else:
        from backend.models import SignalResult
        url_signal = SignalResult(
            name="URL / Domain Reputation",
            score=0,
            weight=0.40,
            passed=True,
            detail="VirusTotal API key not configured — URL check skipped.",
        )
    signals.append(url_signal)

    # 4. Content heuristics
    content_signal = analyze_content(
        body=payload.body or "",
        subject=payload.subject or "",
        from_name=payload.from_name or "",
        from_email=payload.from_email,
    )
    signals.append(content_signal)

    # --- Score aggregation ---
    # Weighted average of all non-blocklist signals
    active_signals = [s for s in signals if s.name != "Personal Blocklist"]
    total_weight = sum(s.weight for s in active_signals)
    if total_weight > 0:
        weighted_score = sum(s.score * s.weight for s in active_signals) / total_weight
    else:
        weighted_score = 0

    total_score = round(weighted_score)
    verdict = compute_verdict(total_score)

    result = ScanResult(
        message_id=payload.message_id,
        from_email=payload.from_email,
        subject=payload.subject or "",
        total_score=total_score,
        verdict=verdict,
        signals=signals,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )
    save_scan(result)
    return result


@app.get("/history")
def get_history(x_api_key: str | None = Header(default=None)):
    """Returns the last 100 scanned emails."""
    require_api_key(x_api_key)
    return load_history()


@app.get("/blocklist")
def list_blocklist(x_api_key: str | None = Header(default=None)):
    require_api_key(x_api_key)
    return {"blocklist": get_blocklist()}


@app.post("/blocklist/{email}")
def block_sender(email: str, x_api_key: str | None = Header(default=None)):
    require_api_key(x_api_key)
    add_to_blocklist(email)
    return {"message": f"{email} added to blocklist"}


@app.delete("/blocklist/{email}")
def unblock_sender(email: str, x_api_key: str | None = Header(default=None)):
    require_api_key(x_api_key)
    remove_from_blocklist(email)
    return {"message": f"{email} removed from blocklist"}


@app.get("/health")
def health():
    return {"status": "ok"}
