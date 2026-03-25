# AGENTS.md

## Project Context

Risk-CTF has two Python components:

- **Monitor**: runs on endpoint hosts, collects security-relevant activity (logs, shell history, optional integrity baselines), and sends **HMAC-signed** events to the Mothership over **HTTPS**.
- **Mothership**: validates and stores events in **SQLite**, serves the **TLS** Monitor API, and serves the **dashboard** (fictional world map, activity feed, multi-user highlights).

**Version:** see `version` in [`pyproject.toml`](pyproject.toml) (currently **0.2.1**).

**Runtime dependencies:** none beyond the Python standard library (`pyproject.toml` `[project] dependencies = []`). Optional **`[project.optional-dependencies] dev`** installs **`cryptography`** for [`tools/gen_dev_certs.py`](tools/gen_dev_certs.py) and the **`deploy/setup_*`** scripts. **Not** imported by `risk_ctf` at runtime.

## Primary Requirements

- Keep **Monitor API** traffic on **TLS** (`register` + `events` on the main HTTPS port).
- The **dashboard** may use a **separate plain-HTTP port** (read-only: `GET /dashboard`, `GET /api/v1/dashboard/state`, `GET /healthz`, `GET /` redirect). **Never** expose authenticated `POST` API routes there (handlers return **403**).
- Authenticate API requests (**HMAC**); use **constant-time** signature compare.
- Enforce **anti-replay** (timestamp skew window + per-monitor nonce tracking).
- Validate **all** event envelopes with [`risk_ctf.common.schema`](src/risk_ctf/common/schema.py); **fail closed** on bad input.
- **Least privilege** for the Monitor; avoid shell injection (no `shell=True`; defensive parsing only).

## Packaging and install

- Editable install: `pip install -e .` (package root: `src/` per `[tool.setuptools]`).
- Development stack: `pip install -e ".[dev]"` (pulls `cryptography` for local TLS cert generation only).
- **Automated setup** (repo root): create `.venv`, install dependencies, and in dev (unless skipped) run **`tools/gen_dev_certs.py`** when `cert.pem` / `key.pem` are missing:
  - `deploy/setup_mothership.ps1` or `deploy/setup_mothership.sh`
  - `deploy/setup_monitor.ps1` or `deploy/setup_monitor.sh`
  - Flags: **Production** / `--production` / `RISK_CTF_PRODUCTION=1` → runtime-only install, no certs; **SkipCert** / `--skip-cert`; **NoVenv** / `--no-venv`.
- Entry points: **`risk-ctf-monitor`**, **`risk-ctf-mothership`** (wrappers for `python -m risk_ctf.monitor` / `risk_ctf.mothership`).

## Repo structure

| Path | Role |
|------|------|
| `src/risk_ctf/common` | Contracts, schema (`ALLOWED_EVENT_TYPES`), HMAC helpers |
| `src/risk_ctf/monitor` | Agent, collector (Phase 2 heuristics), Mothership client |
| `src/risk_ctf/mothership` | Threaded HTTPS/HTTP servers, ledger, dashboard HTML |
| `src/risk_ctf/mothership/world_map.py` | Fictional map JSON (`world`); 10 nations = ledger `COUNTRIES`; adjacency; starter UI players |
| `tools/gen_dev_certs.py` | Dev-only TLS keypair (`cert.pem`, `key.pem`); requires `cryptography` from **`[dev]`** |
| `tests` | `unittest` suite; run with `PYTHONPATH=src` or after `pip install -e .` |
| `deploy` | **Setup:** `setup_mothership.ps1` / `.sh`, `setup_monitor.ps1` / `.sh`, **run:** `start_*.ps1`, `*.service.example` (Linux) |

## Mothership runtime

- **HTTPS** (`--port`, default `8443`): `POST /api/v1/monitors/register`, `POST /api/v1/events`, `GET /dashboard`, `GET /api/v1/dashboard/state`, `GET /healthz`.
- **HTTP** (`--http-dashboard-port`, default `8080`; **`0` = off**): dashboard-only GET routes; no API writes.
- **SQLite + threads:** one connection, `check_same_thread=False`, all DB access under a **`threading.Lock`**. Preserve this invariant if you change persistence.

## Dashboard data model

- `ledger.dashboard_state()` supplies **`user_colors`**, **`countries`**, **`moves`**, **`players_legend`**, **`activity_feed`** (Phase 2).
- `enrich_dashboard_state(state)` adds **`world`** (map geometry, fictional labels, static starter players).
- Map **multi-color** nations when multiple users appear on the same ledger nation; **popups** ~**3s** for first-seen user/nation in the client script.

## Monitor event types (ingest)

Authoritative set: **`risk_ctf.common.schema.ALLOWED_EVENT_TYPES`**

- `user_login`, `sudo_elevation`, `remote_login`
- **Phase 2:** `command_executed`, `tool_download`, `host_reboot`, `tamper_attempt`, `session_terminate`

**Integrity / tamper:** default baseline = `*.py` under the Monitor package (`default_integrity_paths()`). CLI: **`--no-integrity-check`**, **`--integrity-path`** (repeatable). Heuristic only—not EDR-grade.

## Coding standards

- Python **3.11+**; ASCII-by-default in code and typical outputs unless a format requires otherwise.
- Prefer **stdlib**; new third-party deps need strong justification and `pyproject.toml` updates.
- Cross-platform (**Linux + Windows**) unless a change is explicitly OS-specific.
- Preserve **backward compatibility** for existing **routes** and **auth header** contracts when possible.

## Security guardrails

- Never log **secrets**, HMAC keys, or raw auth headers.
- Any new **HTTPS** route that mutates state must require **valid Monitor auth** unless deliberately public (none today).
- Parsers must stay **defensive** (length limits, strict types in schema).

## Testing

- Add or update tests for behavioral changes.
- Minimum: `python -m unittest discover -s tests -p "test_*.py"`.
- Favor adversarial cases for **auth**, **schema**, and **replay** paths.

## Operational commands

- **Setup:** `deploy/setup_mothership.ps1` / `deploy/setup_mothership.sh` and `deploy/setup_monitor.ps1` / `deploy/setup_monitor.sh` (see **Packaging and install** above).
- **Run:** `deploy/start_mothership.ps1`, `deploy/start_monitor.ps1`, or `python -m risk_ctf.mothership` / `python -m risk_ctf.monitor`.
- Mothership requires `--db-path`, `--tls-cert`, `--tls-key`.
- Monitor requires `--mothership-base-url`, `--state-file`; use `--insecure-dev-tls` only for dev self-signed CAs.

## Change management

- Do not edit `.cursor/plans` unless the user asks.
- Keep diffs **focused**; extend existing contracts instead of parallel incompatible ones.
