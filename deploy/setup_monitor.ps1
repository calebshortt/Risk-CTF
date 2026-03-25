# Installs Python dependencies for the Risk-CTF Monitor and (in dev) dev extras + TLS material
# for pairing with a local Mothership using self-signed certs.
# Usage:
#   .\deploy\setup_monitor.ps1
#   .\deploy\setup_monitor.ps1 -Production
#   .\deploy\setup_monitor.ps1 -SkipCert
# Environment: RISK_CTF_PRODUCTION=1 forces production mode.

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
  Write-Host "Installing risk-ctf with dev extras ..."
  pip install -e ".[dev]"
}

if (-not $isProd -and -not $SkipCert) {
  $cert = Join-Path $ProjectRoot "cert.pem"
  $key = Join-Path $ProjectRoot "key.pem"
  if ((Test-Path $cert) -and (Test-Path $key)) {
    Write-Host "cert.pem and key.pem already present (shared with Mothership dev setup)."
  } else {
    Write-Host "Generating development TLS certificate and key (shared with Mothership) ..."
    python (Join-Path $ProjectRoot "tools\gen_dev_certs.py") --output-dir $ProjectRoot
  }
}

Write-Host ""
Write-Host "Monitor setup complete."
Write-Host "Register with the Mothership over HTTPS (use --insecure-dev-tls if the server uses a self-signed cert):"
Write-Host "  python -m risk_ctf.monitor --mothership-base-url https://127.0.0.1:8443 --state-file .\monitor_state.json --insecure-dev-tls"
Write-Host "Or: .\deploy\start_monitor.ps1"
