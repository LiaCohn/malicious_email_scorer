import json
import os
from backend.models import SignalResult

BLOCKLIST_FILE = "data/blocklist.json"


def _load_blocklist() -> list[str]:
    if not os.path.exists(BLOCKLIST_FILE):
        return []
    with open(BLOCKLIST_FILE) as f:
        return json.load(f)


def _save_blocklist(entries: list[str]):
    os.makedirs(os.path.dirname(BLOCKLIST_FILE), exist_ok=True)
    with open(BLOCKLIST_FILE, "w") as f:
        json.dump(entries, f, indent=2)


def add_to_blocklist(email: str):
    entries = _load_blocklist()
    normalized = email.lower()
    if normalized not in entries:
        entries.append(normalized)
        _save_blocklist(entries)


def remove_from_blocklist(email: str):
    entries = _load_blocklist()
    entries = [e for e in entries if e != email.lower()]
    _save_blocklist(entries)


def get_blocklist() -> list[str]:
    return _load_blocklist()


def check_blocklist(from_email: str) -> SignalResult:
    """Returns a max-score signal if sender is in the personal blocklist."""
    blocklist = _load_blocklist()
    blocked = from_email.lower() in blocklist

    return SignalResult(
        name="Personal Blocklist",
        score=100 if blocked else 0,
        weight=1.0 if blocked else 0.0,  # Blocklist is always an override
        passed=not blocked,
        detail=f"Sender {from_email} is in your personal blocklist." if blocked else "Sender not in blocklist.",
    )
