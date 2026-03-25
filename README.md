# Risk-CTF

Risk-CTF is a two-part Python project:

- **Monitor**: runs on Linux and Windows hosts, collects security-relevant activity from logs and shell history, and sends signed events to the Mothership over **HTTPS**.
- **Mothership**: validates and stores events, exposes a **TLS** API for Monitors, and serves an optional **HTTP** dashboard with a fictional world map.

**Packaging:** stdlib-only at runtime (`dependencies` in [`pyproject.toml`](pyproject.toml) is empty). The optional **`dev`** extra installs **`cryptography`** for [`tools/gen_dev_certs.py`](tools/gen_dev_certs.py) and the automated setup scripts (`pip install -e ".[dev]"`).

**Version:** see `version` in [`pyproject.toml`](pyproject.toml) (currently **0.2.1**).

## Automated setup (recommended)

From the **repository root**, use the scripts that create a **`.venv`**, install the package, and (in **development** mode) generate **`cert.pem`** / **`key.pem`** via [`tools/gen_dev_certs.py`](tools/gen_dev_certs.py) when those files are missing.

| Role | Windows (PowerShell) | Linux / macOS (bash) |
|------|----------------------|----------------------|
| **Mothership** | `.\deploy\setup_mothership.ps1` | `./deploy/setup_mothership.sh` |
| **Monitor** | `.\deploy\setup_monitor.ps1` | `./deploy/setup_monitor.sh` |

| Mode | Behavior |
|------|----------|
| **Development (default)** | `pip install -e ".[dev]"`; creates dev TLS certs if absent. |
| **Production-style** | `-Production` (PowerShell) or `--production` / `RISK_CTF_PRODUCTION=1` — `pip install -e .` only; no cert step. |
| **Skip certs only** | `-SkipCert` or `--skip-cert` |
| **Own venv** | `-NoVenv` or `--no-venv` |

After setup, start services with [`deploy/start_mothership.ps1`](deploy/start_mothership.ps1) / [`deploy/start_monitor.ps1`](deploy/start_monitor.ps1) or the `python -m risk_ctf.*` commands below.

## Feature summary

| Area | What is included |
|------|------------------|
| **Transport / API** | TLS for Monitor traffic; HMAC request signing; timestamp + nonce anti-replay; strict JSON schemas. |
| **Mothership** | SQLite ledger; HTTPS listener for register + ingest; optional second listener for dashboard-only HTTP (`--http-dashboard-port`, default `8080`, use `0` to disable). |
| **Dashboard** | Fictional map (10 host-nations), scenario starter players, multi-user color highlights, movement edges, recent **activity feed**, ~3s capture popups. |
| **Monitor (Phase 2)** | Event types: `user_login`, `sudo_elevation`, `remote_login`, `command_executed`, `tool_download`, `host_reboot`, `tamper_attempt`, `session_terminate`. Optional **integrity** baseline on Monitor `*.py` files (tamper hints). |

## Manual quick start (alternative to setup scripts)

1. **Environment:** `python -m venv .venv` → activate → `pip install -e .` or `pip install -e ".[dev]"` if you need cert generation.

2. **TLS material:** place your own `cert.pem` / `key.pem` in the project root, or run `python tools/gen_dev_certs.py` after installing **`[dev]`**.

3. **Mothership:**

   ```text
   python -m risk_ctf.mothership --host 127.0.0.1 --port 8443 --http-dashboard-port 8080 --db-path ./mothership.db --tls-cert ./cert.pem --tls-key ./key.pem
   ```

   - **API (HTTPS):** `https://127.0.0.1:8443`
   - **Dashboard (HTTP):** `http://127.0.0.1:8080/dashboard`

   Console aliases: **`risk-ctf-mothership`** (after `pip install -e .`).

4. **Monitor:**

   ```text
   python -m risk_ctf.monitor --mothership-base-url https://127.0.0.1:8443 --state-file ./monitor_state.json --insecure-dev-tls
   ```

   Useful flags: `--no-integrity-check`, `--integrity-path`, `--auth-log-path`, `--secure-log-path`, `--shell-history-path`.  
   Console alias: **`risk-ctf-monitor`**.

## Windows vs Linux

- **Monitor** defaults are platform-aware (`risk_ctf.monitor.collector.default_collector_paths()`).
- **Windows:** `deploy/setup_*.ps1`, `deploy/start_*.ps1`.
- **Unix:** `deploy/setup_*.sh` (use `chmod +x` once if needed).
- **Linux** service examples: `deploy/monitor.service.example`, `deploy/mothership.service.example`.

## Tests

From the repo root (with the package on `PYTHONPATH`):

```text
set PYTHONPATH=src
python -m unittest discover -s tests -p "test_*.py"
```

If you used `pip install -e .`, you can omit `PYTHONPATH`.

## Further reading

- **[AGENTS.md](AGENTS.md)** — conventions, security guardrails, and architecture notes for contributors and coding agents.
