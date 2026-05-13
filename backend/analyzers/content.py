import json
import os
import re
from typing import Any

import httpx
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
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.1-8b-instant"


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


def _analyze_content_rules(body: str, subject: str, from_name: str, from_email: str) -> tuple[int, list[str]]:
    text = f"{subject} {body}".lower()
    triggered = []

    for pattern, label in PHISHING_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            triggered.append(label)

    # Remove duplicates while preserving order
    triggered_unique = list(dict.fromkeys(triggered))
    name_mismatch = _check_display_name_mismatch(from_name, from_email)

    # Check for suspicious TLD in sender domain
    try:
        domain = from_email.split("@")[1]
        suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    except IndexError:
        suspicious_tld = False

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
        details.append("Sender domain uses a suspicious TLD")

    return min(score, 100), details


def _extract_json_object(raw: str) -> dict[str, Any] | None:
    raw = raw.strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return None


def _analyze_content_llm(body: str, subject: str, from_name: str, from_email: str) -> dict[str, Any] | None:
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not api_key:
        return None

    # Keep bounded input to control latency/cost.
    body = body[:3000]
    prompt = (
        "Analyze this email for phishing/malicious social-engineering risk.\n"
        "Return JSON only with keys: risk_score, confidence, reasons.\n"
        "Constraints:\n"
        "- risk_score: integer 0-100\n"
        "- confidence: float 0-1\n"
        "- reasons: array of 1-3 short strings\n"
        "No markdown, no extra keys.\n\n"
        f"From name: {from_name}\n"
        f"From email: {from_email}\n"
        f"Subject: {subject}\n"
        f"Body: {body}\n"
    )
    payload = {
        "model": GROQ_MODEL,
        "temperature": 0.1,
        "max_tokens": 180,
        "messages": [
            {"role": "system", "content": "You are a phishing email risk classifier."},
            {"role": "user", "content": prompt},
        ],
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.post(GROQ_API_URL, headers=headers, json=payload)
        if resp.status_code != 200:
            return None
        data = resp.json()
        raw_content = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        parsed = _extract_json_object(raw_content)
        if not parsed:
            return None
        return parsed
    except Exception:
        return None


def _merge_rule_and_llm_score(rule_score: int, llm_score: int, llm_confidence: float) -> int:
    llm_confidence = max(0.0, min(float(llm_confidence), 1.0))
    llm_score = max(0, min(int(llm_score), 100))
    adjusted_llm = llm_score * llm_confidence

    # Rule baseline remains intact; LLM can increase risk with confidence.
    merged = max(
        rule_score,
        round(0.65 * rule_score + 0.35 * adjusted_llm),
        round(0.70 * adjusted_llm),
    )
    return max(0, min(int(merged), 100))


def analyze_content(body: str, subject: str, from_name: str, from_email: str) -> SignalResult:
    """
    Hybrid content analyzer:
    - deterministic rule-based phishing heuristics
    - optional LLM semantic risk assessment via Groq
    """
    rule_score, rule_details = _analyze_content_rules(
        body=body,
        subject=subject,
        from_name=from_name,
        from_email=from_email,
    )

    llm = _analyze_content_llm(
        body=body,
        subject=subject,
        from_name=from_name,
        from_email=from_email,
    )

    score = rule_score
    details = list(rule_details)
    if llm:
        llm_score = llm.get("risk_score", 0)
        try:
            llm_confidence = float(llm.get("confidence", 0.0))
        except (TypeError, ValueError):
            llm_confidence = 0.0
        llm_confidence = max(0.0, min(llm_confidence, 1.0))
        llm_reasons = llm.get("reasons", [])
        if isinstance(llm_reasons, list):
            llm_reasons = [str(r).strip() for r in llm_reasons if str(r).strip()][:3]
        else:
            llm_reasons = []

        score = _merge_rule_and_llm_score(
            rule_score=rule_score,
            llm_score=llm_score,
            llm_confidence=llm_confidence,
        )
        if llm_reasons and llm_confidence >= 0.2:
            details.append(
                "LLM semantic review: "
                + "; ".join(llm_reasons)
                + f" (confidence {llm_confidence:.2f})"
            )

    passed = score < 30
    detail = "; ".join(details) if details else "No suspicious content patterns detected."

    return SignalResult(
        name="Content Heuristics",
        score=score,
        weight=0.35,
        passed=passed,
        detail=detail,
    )
