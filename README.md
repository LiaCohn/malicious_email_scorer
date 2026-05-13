# Email Maliciousness Scorer — Gmail Add-on

A Gmail Add-on that analyzes opened emails and produces a risk score with an explainable verdict.

---

## Architecture

```
Gmail Add-on (Apps Script)
    │  sends email data (headers, body, URLs) via HTTP POST
    ▼
Python FastAPI Backend  (runs locally, exposed via ngrok)
    ├── Header Analyzer     → SPF / DKIM / DMARC authentication
    ├── URL Analyzer        → VirusTotal reputation check
    ├── Content Analyzer    → Phishing heuristics (regex)
    └── Blocklist Checker   → Personal sender blocklist
    │
    └── Weighted score → SAFE / SUSPICIOUS / MALICIOUS
```

The add-on sidebar shows:
- Score (0–100) and verdict
- Each signal's result with explanation
- "Block sender" button
- Scan history (last 100 emails)

---

## Signals & Scoring

| Signal | Weight | What it checks |
|--------|--------|----------------|
| SPF/DKIM/DMARC | 25% | Did the sending server authenticate correctly? |
| URL Reputation | 40% | Are any URLs flagged by VirusTotal? |
| Content Heuristics | 35% | Phishing language, brand impersonation, suspicious TLDs |
| Personal Blocklist | Override | Always MALICIOUS if sender is blocked |

**Verdict thresholds:**
- 0–34 → ✅ SAFE
- 35–69 → ⚠️ SUSPICIOUS
- 70–100 → 🔴 MALICIOUS

---

## Running Locally

### 1. Clone and install

```bash
git clone <repo>
cd email-scorer
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and add your VirusTotal key + backend API key
```

### 3. Start the backend

```bash
uvicorn backend.main:app --reload --port 8000
```

### 4. Expose via ngrok

```bash
ngrok http 8000
# Copy the https URL, e.g. https://abc123.ngrok.io
```

### 5. Set up the Gmail Add-on

1. Go to [script.google.com](https://script.google.com) → New project
2. Copy `addon/Code.gs` contents into `Code.gs`
3. Copy `addon/appsscript.json` into the manifest (Project Settings → Show manifest)
4. In `Code.gs`, replace `BACKEND_URL` with your ngrok URL
5. In `Code.gs`, set `BACKEND_API_KEY` to match your backend `.env`
6. Click **Deploy → Test deployments → Gmail**
7. Open any email in Gmail — the add-on sidebar will appear

---

## APIs Used

- **VirusTotal v3 API** — URL and domain reputation. Free tier: 4 requests/minute.
  - Endpoint: `GET /urls/{id}`, `POST /urls`
  - Get your key at: https://virustotal.com

- **Gmail Apps Script API** — reads message content, headers, sender info.

- **Google Apps Script UrlFetchApp** — makes HTTP requests from the add-on to the backend.

---

## Implemented Features

- [x] SPF / DKIM / DMARC header analysis
- [x] URL extraction + VirusTotal reputation check
- [x] Content heuristics (phishing phrases, brand impersonation, suspicious TLDs)
- [x] Personal sender blocklist (add/remove via UI)
- [x] Scan history (last 100 emails, stored in JSON)
- [x] Explainable verdict — each signal shows its contribution

---

## Known Limitations


- **VirusTotal rate limit**: Free tier is 4 requests/minute. Emails with many URLs may hit this limit; the code limits checks to 5 URLs per email.

- **Static heuristic lists**: Brand list and suspicious TLDs are hardcoded. In production these would be loaded from a configurable source or external threat feed.

- **ngrok URL changes**: Every time ngrok restarts, the URL changes and `Code.gs` must be updated manually. A stable deployment (e.g. Railway, Render) would solve this.

- **Simple API key auth**: This demo uses a shared API key via `X-API-Key`. It is enough for assignment scope, but production should use stronger service-to-service auth and key rotation.

- **Local file storage**: Blocklist and scan history are stored in local JSON files. This is fine for demo scope but should be replaced with a database for multi-user or cloud deployment.

---

## Future Improvements

- Move static heuristics (brand/TLD lists) to configurable policy storage and optional external threat-intel feeds.
- Add stronger service authentication/authorization (signed service identity, secret rotation, per-tenant access control).
- Replace local JSON persistence with a database and add basic observability (structured logs, error metrics, rate-limit monitoring).
# malicious_email_scorer
