import json
import os
from backend.models import ScanResult

HISTORY_FILE = "data/history.json"
MAX_HISTORY = 100


def save_scan(result: ScanResult):
    history = load_history()
    # Avoid duplicate scans of the same message
    history = [h for h in history if h["message_id"] != result.message_id]
    history.insert(0, result.model_dump())
    history = history[:MAX_HISTORY]

    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def load_history() -> list[dict]:
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE) as f:
        return json.load(f)
