from backend.models import SignalResult


def analyze_headers(headers: dict) -> SignalResult:
    """
    Checks SPF, DKIM, and DMARC authentication results from email headers.
    These are set by mail servers and indicate whether the sender is legitimate.
    """
    failures = []
    checks = {
        "spf": False,
        "dkim": False,
        "dmarc": False,
    }

    # Normalize header keys to lowercase for easier lookup
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    # --- SPF ---
    # "Received-SPF" header is set by the receiving mail server
    spf_raw = headers_lower.get("received-spf", "")
    if spf_raw.startswith("pass"):
        checks["spf"] = True
    elif spf_raw:
        failures.append("SPF failed")

    # --- DKIM ---
    # "Authentication-Results" header contains DKIM result
    auth_results = headers_lower.get("authentication-results", "")
    if "dkim=pass" in auth_results:
        checks["dkim"] = True
    elif "dkim=" in auth_results:
        failures.append("DKIM failed")

    # --- DMARC ---
    if "dmarc=pass" in auth_results:
        checks["dmarc"] = True
    elif "dmarc=" in auth_results:
        failures.append("DMARC failed")

    num_failures = len(failures)
    # If we have no headers at all, treat as unknown (neutral)
    if not spf_raw and "dkim=" not in auth_results:
        return SignalResult(
            name="Email Authentication (SPF/DKIM/DMARC)",
            score=20,
            weight=0.25,
            passed=True,
            detail="Authentication headers not available — unable to verify sender.",
        )

    if num_failures == 0:
        score = 0
        detail = "SPF, DKIM, and DMARC all passed — sender identity verified."
        passed = True
    elif num_failures == 1:
        score = 40
        detail = f"Minor authentication issue: {', '.join(failures)}."
        passed = False
    elif num_failures == 2:
        score = 70
        detail = f"Authentication failures: {', '.join(failures)}."
        passed = False
    else:
        score = 100
        detail = "All authentication checks failed — high risk of spoofed sender."
        passed = False

    return SignalResult(
        name="Email Authentication (SPF/DKIM/DMARC)",
        score=score,
        weight=0.25,
        passed=passed,
        detail=detail,
    )
