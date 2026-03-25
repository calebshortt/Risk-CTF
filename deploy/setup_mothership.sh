#!/usr/bin/env bash
# Installs Python dependencies for the Risk-CTF Mothership and (in dev) TLS certificates.
# Usage:
#   ./deploy/setup_mothership.sh
#   RISK_CTF_PRODUCTION=1 ./deploy/setup_mothership.sh
#   ./deploy/setup_mothership.sh --production
#   ./deploy/setup_mothership.sh --skip-cert

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PRODUCTION=0
SKIP_CERT=0
NO_VENV=0
for arg in "$@"; do
  case "$arg" in
    --production) PRODUCTION=1 ;;
    --skip-cert) SKIP_CERT=1 ;;
    --no-venv) NO_VENV=1 ;;
  esac
done
if [[ -n "${RISK_CTF_PRODUCTION:-}" ]]; then
  PRODUCTION=1
fi

echo "Project root: $ROOT"
if [[ "$PRODUCTION" -eq 1 ]]; then
  echo "Mode: production"
else
  echo "Mode: development"
fi

if [[ "$NO_VENV" -eq 0 ]]; then
  if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
    echo "Creating virtual environment .venv ..."
    python3 -m venv .venv
  fi
  # shellcheck source=/dev/null
  source "$ROOT/.venv/bin/activate"
fi

python -m pip install --upgrade pip
if [[ "$PRODUCTION" -eq 1 ]]; then
  echo "Installing risk-ctf (runtime only) ..."
  pip install -e .
else
  echo "Installing risk-ctf with dev extras (cryptography for TLS cert generation) ..."
  pip install -e ".[dev]"
fi

if [[ "$PRODUCTION" -eq 0 && "$SKIP_CERT" -eq 0 ]]; then
  if [[ -f "$ROOT/cert.pem" && -f "$ROOT/key.pem" ]]; then
    echo "cert.pem and key.pem already exist; skipping certificate generation."
  else
    echo "Generating development TLS certificate and key ..."
    python "$ROOT/tools/gen_dev_certs.py" --output-dir "$ROOT"
  fi
fi

echo ""
echo "Mothership setup complete."
echo "Start server:"
echo "  python -m risk_ctf.mothership --host 127.0.0.1 --port 8443 --http-dashboard-port 8080 --db-path ./mothership.db --tls-cert ./cert.pem --tls-key ./key.pem"
