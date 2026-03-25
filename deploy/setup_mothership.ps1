# Installs Python dependencies for the Risk-CTF Mothership and (in dev) TLS certificates.
# Usage:
#   .\deploy\setup_mothership.ps1
#   .\deploy\setup_mothership.ps1 -Production
#   .\deploy\setup_mothership.ps1 -SkipCert
# Environment: set RISK_CTF_PRODUCTION=1 to force production mode (no dev extras, no certs).

param(
  [switch]$Production,
  [switch]$SkipCert,
  [switch]$NoVenv,
  [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"
if (-not $ProjectRoot) {
  $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
Set-Location $ProjectRoot

$isProd = $Production -or ($env:RISK_CTF_PRODUCTION -eq "1")

Write-Host "Project root: $ProjectRoot"
Write-Host "Mode: $(if ($isProd) { 'production' } else { 'development' })"

if (-not $NoVenv) {
  $venvPy = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
  if (-not (Test-Path $venvPy)) {
    Write-Host "Creating virtual environment .venv ..."
    python -m venv .venv
  }
  & (Join-Path $ProjectRoot ".venv\Scripts\Activate.ps1")
}

python -m pip install --upgrade pip
if ($isProd) {
  Write-Host "Installing risk-ctf (runtime only) ..."
  pip install -e .
} else {
  Write-Host "Installing risk-ctf with dev extras (cryptography for TLS cert generation) ..."
  pip install -e ".[dev]"
}

if (-not $isProd -and -not $SkipCert) {
  $cert = Join-Path $ProjectRoot "cert.pem"
  $key = Join-Path $ProjectRoot "key.pem"
  if ((Test-Path $cert) -and (Test-Path $key)) {
    Write-Host "cert.pem and key.pem already exist; skipping certificate generation."
  } else {
    Write-Host "Generating development TLS certificate and key ..."
    python (Join-Path $ProjectRoot "tools\gen_dev_certs.py") --output-dir $ProjectRoot
  }
}

Write-Host ""
Write-Host "Mothership setup complete."
Write-Host "Start server (from project root, with .venv active):"
Write-Host "  python -m risk_ctf.mothership --host 127.0.0.1 --port 8443 --http-dashboard-port 8080 --db-path .\mothership.db --tls-cert .\cert.pem --tls-key .\key.pem"
Write-Host "Or: .\deploy\start_mothership.ps1"
