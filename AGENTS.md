# AGENTS.md

## Project Context

Risk-CTF has two Python components:

- `Monitor`: runs on endpoint hosts, collects security-relevant activity, and sends signed/encrypted events.
- `Mothership`: receives monitor events, validates/authenticates them, stores ledger state, and serves the dashboard/API.

Current codebase is an MVP with stdlib-first design: **no required runtime third-party packages** (see `pyproject.toml` `dependencies`).

## Primary Requirements

- Keep **monitor API** transport encrypted (TLS): registration and event ingest must use HTTPS.
- The **dashboard** may optionally be exposed on plain HTTP on a **separate port** (read-only UI and `GET /api/v1/dashboard/state`). **Do not** add authenticated API routes on that listener (`POST` there returns 403).
- Keep API requests authenticated (HMAC signatures).
- Enforce anti-replay protection (timestamp window + nonce tracking).
- Validate event schemas strictly and fail closed on bad input.
- Prefer least-privilege operation and avoid introducing command-injection risk.

## Packaging and Dependencies

- Install: `pip install -e .` from the repo root (uses `src/` layout per `pyproject.toml`).
- Optional dev extra for local TLS **certificate generation** when OpenSSL is missing: `pip install -e ".[dev]"` (pulls `cryptography`; **not** imported by `risk_ctf` at runtime).
- Console entry points after install: `risk-ctf-monitor`, `risk-ctf-mothership` (same CLIs as `python -m risk_ctf.monitor` / `python -m risk_ctf.mothership`).

## Repo Structure

- `src/risk_ctf/common`: shared contracts, schema validation, crypto/auth helpers
- `src/risk_ctf/monitor`: monitor agent, collectors, mothership client
- `src/risk_ctf/mothership`: HTTPS API server, ledger persistence, dashboard HTML, fictional map metadata
- `src/risk_ctf/mothership/world_map.py`: fictional world map payload for the dashboard (10 host-nations aligned with ledger `COUNTRIES`, adjacency for drawing, two starter players for UI positioning)
- `tests`: unit/integration/security tests (`PYTHONPATH=src` or editable install)
- `deploy`: Linux `systemd` examples and Windows PowerShell startup scripts

## Mothership Runtime Behavior

- **HTTPS** (main `--port`, default 8443): `POST /api/v1/monitors/register`, `POST /api/v1/events`, `GET /dashboard`, `GET /api/v1/dashboard/state`, `GET /healthz`.
- **HTTP** (optional `--http-dashboard-port`, default **8080**; use **0** to disable): only `GET /`, `GET /dashboard`, `GET /api/v1/dashboard/state`, `GET /healthz`; **no** API registration or ingest.
- **Ledger / SQLite**: a single shared connection is used from `ThreadingHTTPServer` worker threads. The implementation uses `check_same_thread=False` and a `threading.Lock` around DB access. If you change storage, preserve thread safety or switch to per-thread connections.

## Dashboard

- Ingested activity still drives `dashboard_state()` (users, moves). `enrich_dashboard_state()` merges a static **fictional** map layer (`world` in JSON) for visualization; ledger keys remain the `COUNTRIES` list (ten slots = ten Monitors).

## Coding Standards

- Language: Python 3.11+.
- Prefer Python standard library unless a dependency is clearly justified.
- Keep modules focused and explicit; avoid hidden side effects.
- Use ASCII by default in files and outputs.
- Maintain cross-platform behavior (Linux + Windows) unless change is explicitly platform-specific.
- Preserve backward compatibility for existing API routes and header contracts.

## Security Guardrails

- Never log secrets, HMAC keys, or full auth headers.
- Use constant-time comparison for signatures.
- Reject requests with missing/invalid auth metadata.
- Keep parser logic defensive and explicit for all event fields.
- Any new endpoint must include auth checks unless intentionally public.

## Testing Expectations

- Add or update tests for every substantive behavior change.
- At minimum run:
  - `python -m unittest discover -s tests -p "test_*.py"`
- Include adversarial test coverage for auth/schema/replay-sensitive code paths when applicable.

## Operational Notes

- Mothership: `python -m risk_ctf.mothership ...` or `risk-ctf-mothership ...` (TLS cert/key required; see README for flags).
- Monitor: `python -m risk_ctf.monitor ...` or `risk-ctf-monitor ...`
- Windows helpers:
  - `deploy/start_mothership.ps1`
  - `deploy/start_monitor.ps1`

## Change Management

- Do not edit plan artifacts in `.cursor/plans` unless explicitly requested.
- Keep edits minimal, targeted, and aligned with the existing MVP architecture.
- Prefer extending existing contracts over introducing parallel/incompatible ones.
