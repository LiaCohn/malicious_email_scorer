import re
from backend.models import SignalResult


# Common phishing phrases — urgency, threats, credential requests
PHISHING_PATTERNS = [
    (r"\bverify your account\b", "credential request"),
    (r"\bconfirm your (password|identity|details)\b", "credential request"),
    (r"\bclick here (immediately|now|urgently)\b", "urgency"),
    (r"\byour account (will be|has been) (suspended|locked|terminated)\b", "account threat"),
    (r"\bunusual (sign-?in|activity|login)\b", "account threat"),
    (r"\bact (now|immediately|fast)\b", "urgency"),
    (r"\blimited time\b", "urgency"),
    (r"\byou (have won|are selected|are a winner)\b", "scam"),
    (r"\bclaim your (prize|reward|gift)\b", "scam"),
    (r"\benter your (credit card|ssn|social security|bank)\b", "sensitive data request"),
    (r"\bupdate your (billing|payment) (information|details)\b", "sensitive data request"),
    (r"\bwe noticed suspicious\b", "fake security alert"),
    (r"\byour (paypal|apple|amazon|netflix|bank) account\b", "brand impersonation"),
]

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = {".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw"}


def _check_display_name_mismatch(from_name: str, from_email: str) -> bool:
    """
    Detects when display name claims to be a known brand
    but the actual email domain doesn't match.
    e.g. "PayPal Security <support@mail-secure-paypal.ru>"
    """
    known_brands = ["paypal", "apple", "amazon", "google", "microsoft", "netflix", "facebook", "instagram", "bank"]
    name_lower = from_name.lower()
    email_lower = from_email.lower()

    for brand in known_brands:
        if brand in name_lower and brand not in email_lower:
            return True
    return False


def analyze_content(body: str, subject: str, from_name: str, from_email: str) -> SignalResult:
    """
    Scans email content for phishing patterns using regex heuristics.
    """
    text = f"{subject} {body}".lower()
    triggered = []

    for pattern, label in PHISHING_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            triggered.append(label)

    # Remove duplicates while preserving order
    triggered_unique = list(dict.fromkeys(triggered))

    # Check for display name mismatch (common in brand impersonation)
    name_mismatch = _check_display_name_mismatch(from_name, from_email)

    # Check for suspicious TLD in sender domain
    try:
        domain = from_email.split("@")[1]
        suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    except IndexError:
        suspicious_tld = False

    # Build score
    score = 0
    details = []

    if triggered_unique:
        score += min(len(triggered_unique) * 20, 60)
        details.append(f"Phishing language detected: {', '.join(triggered_unique)}")

    if name_mismatch:
        score += 30
        details.append("Sender display name impersonates a known brand")

    if suspicious_tld:
        score += 20
        details.append(f"Sender domain uses a suspicious TLD")

    score = min(score, 100)
    passed = score < 30

    detail = "; ".join(details) if details else "No suspicious content patterns detected."

    return SignalResult(
        name="Content Heuristics",
        score=score,
        weight=0.35,
        passed=passed,
        detail=detail,
    )
