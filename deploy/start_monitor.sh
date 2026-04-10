#!/usr/bin/env bash
# Run from repo root after setup (see deploy/setup_monitor.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"

MOTHERSHIP_BASE_URL="${MOTHERSHIP_BASE_URL:-https://127.0.0.1:8443}"
STATE_FILE="${STATE_FILE:-./monitor_state.json}"
SOURCE_COUNTRY="${SOURCE_COUNTRY:-Unknown}"
POLL_SECONDS="${POLL_SECONDS:-10}"

exec python3 -m risk_ctf.monitor \
  --mothership-base-url "$MOTHERSHIP_BASE_URL" \
  --state-file "$STATE_FILE" \
  --source-country "$SOURCE_COUNTRY" \
  --poll-seconds "$POLL_SECONDS" \
  --insecure-dev-tls
