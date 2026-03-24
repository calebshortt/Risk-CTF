param(
  [string]$HostAddr = "127.0.0.1",
  [int]$Port = 8443,
  [int]$HttpDashboardPort = 8080,
  [string]$DbPath = ".\mothership.db",
  [string]$TlsCert = ".\cert.pem",
  [string]$TlsKey = ".\key.pem"
)

$env:PYTHONPATH = "src"
python -m risk_ctf.mothership --host $HostAddr --port $Port --http-dashboard-port $HttpDashboardPort --db-path $DbPath --tls-cert $TlsCert --tls-key $TlsKey
