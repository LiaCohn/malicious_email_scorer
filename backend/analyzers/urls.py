import httpx
import base64
from urllib.parse import urlparse
import ipaddress
from backend.models import SignalResult


VIRUSTOTAL_API = "https://www.virustotal.com/api/v3"
SUSPICIOUS_TLDS = {".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw"}
BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com"],
    "amazon": ["amazon.com"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "netflix": ["netflix.com"],
}


def _vt_url_id(url: str) -> str:
    """VirusTotal expects URLs base64-encoded (no padding) as their ID."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


async def check_url(url: str, api_key: str) -> dict:
    """Check a single URL against VirusTotal. Returns stats dict."""
    url_id = _vt_url_id(url)
    headers = {"x-apikey": api_key}

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{VIRUSTOTAL_API}/urls/{url_id}", headers=headers)

        if resp.status_code == 404:
            # URL not in VT database — submit it for scanning
            scan_resp = await client.post(
                f"{VIRUSTOTAL_API}/urls",
                headers=headers,
                data={"url": url},
            )
            if scan_resp.status_code == 200:
                return {"malicious": 0, "suspicious": 0, "status": "submitted"}
            return {"malicious": 0, "suspicious": 0, "status": "unknown"}

        if resp.status_code != 200:
            return {"malicious": 0, "suspicious": 0, "status": "error"}

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "status": "found",
            "url": url,
        }


def _is_ip_host(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _domain_heuristics(urls: list[str]) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            continue

        if _is_ip_host(host):
            score = max(score, 50)
            reasons.append(f"URL uses direct IP host: {host}")

        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            score = max(score, 40)
            reasons.append(f"URL domain uses suspicious TLD: {host}")

        for brand, legit_domains in BRAND_DOMAINS.items():
            if brand in host and not any(host == d or host.endswith(f".{d}") for d in legit_domains):
                score = max(score, 60)
                reasons.append(f"Possible brand impersonation in URL domain: {host}")
                break

    deduped = list(dict.fromkeys(reasons))
    return score, deduped


async def analyze_urls(urls: list[str], api_key: str) -> SignalResult:
    """
    Checks all URLs in the email against VirusTotal.
    Scores based on worst offender found.
    """
    if not urls:
        return SignalResult(
            name="URL / Domain Reputation",
            score=0,
            weight=0.40,
            passed=True,
            detail="No URLs found in this email.",
        )

    # Deduplicate and limit to 5 URLs (free VT tier: 4 req/min)
    unique_urls = list(dict.fromkeys(urls))[:5]
    results = []
    heuristic_score, heuristic_reasons = _domain_heuristics(unique_urls)

    for url in unique_urls:
        try:
            result = await check_url(url, api_key)
            results.append(result)
        except Exception:
            pass  # Network error — skip this URL

    if not results:
        detail = "Could not reach VirusTotal — URL reputation unknown."
        if heuristic_reasons:
            detail += " Local domain heuristics: " + "; ".join(heuristic_reasons)
        return SignalResult(
            name="URL / Domain Reputation",
            score=max(10, heuristic_score),
            weight=0.40,
            passed=max(10, heuristic_score) < 30,
            detail=detail,
        )

    # Find the most dangerous URL
    max_malicious = max(r.get("malicious", 0) for r in results)
    max_suspicious = max(r.get("suspicious", 0) for r in results)
    flagged_urls = [r["url"] for r in results if r.get("malicious", 0) > 0 or r.get("suspicious", 0) > 0]

    if max_malicious >= 5:
        score = 100
        passed = False
        detail = f"URL flagged as malicious by {max_malicious} security engines."
    elif max_malicious > 0:
        score = 70
        passed = False
        detail = f"URL flagged by {max_malicious} engine(s) as malicious."
    elif max_suspicious > 0:
        score = 40
        passed = False
        detail = f"URL flagged by {max_suspicious} engine(s) as suspicious."
    else:
        score = 0
        passed = True
        detail = f"All {len(unique_urls)} URL(s) checked — none flagged."

    if heuristic_score > score:
        score = heuristic_score
        passed = score < 30
        detail = "Local domain heuristics raised risk: " + "; ".join(heuristic_reasons)
    elif heuristic_reasons:
        detail += " Local domain heuristics noted: " + "; ".join(heuristic_reasons)

    return SignalResult(
        name="URL / Domain Reputation",
        score=score,
        weight=0.40,
        passed=passed,
        detail=detail,
    )
