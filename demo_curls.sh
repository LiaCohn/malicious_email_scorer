#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://localhost:8000"
API_KEY="7cddf67dce57a64e586683b98d73ca08f8291930409472ae0dc997b7551aa403"

echo "== 1) Benign / expected SAFE =="
curl -s -X POST "$BASE_URL/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "message_id": "demo-safe-1",
    "from_email": "newsletter@github.com",
    "from_name": "GitHub",
    "subject": "Your weekly updates",
    "body": "Here are your weekly updates. No action required.",
    "headers": {},
    "urls": ["https://github.com/features"]
  }' | jq .

echo
echo "== 2) Phishing-like / expected SUSPICIOUS =="
curl -s -X POST "$BASE_URL/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "message_id": "demo-susp-1",
    "from_email": "support@paypal-secure.ru",
    "from_name": "PayPal Security",
    "subject": "Urgent: verify your account now",
    "body": "We noticed unusual activity. Click here immediately to verify your account or it will be suspended.",
    "headers": {},
    "urls": ["http://paypal-secure-login.ru/verify"]
  }' | jq .

echo
echo "== 3) IP URL / likely higher risk =="
curl -s -X POST "$BASE_URL/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "message_id": "demo-ip-1",
    "from_email": "alerts@secure-notify.xyz",
    "from_name": "Security Team",
    "subject": "Action required immediately",
    "body": "Unusual sign-in detected. Confirm your identity now.",
    "headers": {},
    "urls": ["http://198.51.100.23/login"]
  }' | jq .

echo
echo "== 4) Blocklist flow demo =="
echo "-- add sender to blocklist --"
curl -s -X POST "$BASE_URL/blocklist/support@paypal-secure.ru" \
  -H "X-API-Key: $API_KEY" | jq .

echo "-- rescan same sender / expected MALICIOUS override --"
curl -s -X POST "$BASE_URL/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "message_id": "demo-blocked-1",
    "from_email": "support@paypal-secure.ru",
    "from_name": "PayPal Security",
    "subject": "Urgent: verify your account now",
    "body": "Click here immediately to verify your account.",
    "headers": {},
    "urls": ["http://paypal-secure-login.ru/verify"]
  }' | jq .

echo
echo "== 5) History endpoint =="
curl -s -X GET "$BASE_URL/history" \
  -H "X-API-Key: $API_KEY" | jq .