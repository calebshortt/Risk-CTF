#!/usr/bin/env bash
# Run from repo root after setup (see deploy/setup_mothership.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8443}"
HTTP_DASHBOARD_PORT="${HTTP_DASHBOARD_PORT:-8080}"
DB_PATH="${DB_PATH:-./mothership.db}"
TLS_CERT="${TLS_CERT:-./cert.pem}"
TLS_KEY="${TLS_KEY:-./key.pem}"

exec python3 -m risk_ctf.mothership \
  --host "$HOST" \
  --port "$PORT" \
  --http-dashboard-port "$HTTP_DASHBOARD_PORT" \
  --db-path "$DB_PATH" \
  --tls-cert "$TLS_CERT" \
  --tls-key "$TLS_KEY"
