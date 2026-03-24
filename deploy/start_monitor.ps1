param(
  [string]$MothershipBaseUrl = "https://127.0.0.1:8443",
  [string]$StateFile = ".\monitor_state.json",
  [string]$SourceCountry = "Unknown",
  [string]$AuthLogPath = "C:\ProgramData\RiskCTF\security.log",
  [string]$SecureLogPath = "C:\ProgramData\ssh\logs\sshd.log",
  [int]$PollSeconds = 5
)

$env:PYTHONPATH = "src"
python -m risk_ctf.monitor --mothership-base-url $MothershipBaseUrl --state-file $StateFile --source-country $SourceCountry --auth-log-path $AuthLogPath --secure-log-path $SecureLogPath --poll-seconds $PollSeconds --insecure-dev-tls
