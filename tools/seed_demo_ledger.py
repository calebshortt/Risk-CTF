#!/usr/bin/env python3
"""Create a SQLite ledger with demo monitors and events for dashboard preview.

Usage (from repo root):
  PYTHONPATH=src python tools/seed_demo_ledger.py
  PYTHONPATH=src python tools/seed_demo_ledger.py --db-path ./my_demo.db

Then start the mothership with the same --db-path.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

# Repo root: tools/ -> parent
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from risk_ctf.common.schema import EventEnvelope  # noqa: E402
from risk_ctf.mothership.ledger import Ledger  # noqa: E402


def _ev(
    *,
    event_type: str,
    event_id: str,
    ts: str,
    monitor_id: str,
    actor_user: str,
    source_host: str,
    source_country: str,
    payload: dict,
) -> dict:
    return EventEnvelope.validate(
        {
            "event_type": event_type,
            "event_id": event_id,
            "ts": ts,
            "monitor_id": monitor_id,
            "actor_user": actor_user,
            "source_host": source_host,
            "source_country": source_country,
            "payload": payload,
        }
    ).to_dict()


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed Risk-CTF demo ledger")
    parser.add_argument(
        "--db-path",
        default=str(_REPO_ROOT / "demo_mothership.db"),
        help="SQLite path to create or replace",
    )
    args = parser.parse_args()
    db_path = Path(args.db_path).resolve()
    if db_path.exists():
        db_path.unlink()

    ledger = Ledger(str(db_path))
    try:
        t0 = int(time.time())
        hosts = [
            ("demo-fp-west-1", "atlas-west-01", "United_States"),
            ("demo-fp-east-1", "atlas-east-01", "Japan"),
            ("demo-fp-south-1", "atlas-south-01", "Brazil"),
        ]
        regs: list[dict[str, str]] = []
        for fp, sh, sc in hosts:
            regs.append(
                ledger.register_monitor(
                    fingerprint=fp,
                    source_host=sh,
                    source_country=sc,
                    created_at_ts=t0,
                )
            )

        def mid(i: int) -> str:
            return regs[i]["monitor_id"]

        def country(i: int) -> str:
            return regs[i]["assigned_country"]

        host = lambda i: hosts[i][1]  # noqa: E731

        events_spec: list[tuple[str, dict]] = [
            (
                "e_login_1",
                _ev(
                    event_type="user_login",
                    event_id="e_login_1",
                    ts="2026-04-10T10:00:05Z",
                    monitor_id=mid(0),
                    actor_user="alice",
                    source_host=host(0),
                    source_country=country(0),
                    payload={"source_ip": "203.0.113.44"},
                ),
            ),
            (
                "e_sudo_1",
                _ev(
                    event_type="sudo_elevation",
                    event_id="e_sudo_1",
                    ts="2026-04-10T10:02:11Z",
                    monitor_id=mid(0),
                    actor_user="alice",
                    source_host=host(0),
                    source_country=country(0),
                    payload={"method": "sudo"},
                ),
            ),
            (
                "e_cmd_1",
                _ev(
                    event_type="command_executed",
                    event_id="e_cmd_1",
                    ts="2026-04-10T10:03:00Z",
                    monitor_id=mid(0),
                    actor_user="alice",
                    source_host=host(0),
                    source_country=country(0),
                    payload={
                        "command_line": "kubectl get pods -n production",
                        "executed_command": "kubectl get pods -n production",
                    },
                ),
            ),
            (
                "e_dl_1",
                _ev(
                    event_type="tool_download",
                    event_id="e_dl_1",
                    ts="2026-04-10T10:04:22Z",
                    monitor_id=mid(0),
                    actor_user="alice",
                    source_host=host(0),
                    source_country=country(0),
                    payload={
                        "channel": "curl",
                        "target": "https://releases.example/tool.tar.gz -o /tmp/tool.tar.gz",
                    },
                ),
            ),
            (
                "e_ssh_1",
                _ev(
                    event_type="remote_login",
                    event_id="e_ssh_1",
                    ts="2026-04-10T10:05:40Z",
                    monitor_id=mid(0),
                    actor_user="alice",
                    source_host=host(0),
                    source_country=country(0),
                    payload={
                        "destination_host": "bastion-east",
                        "destination_country": country(1),
                        "protocol": "ssh",
                    },
                ),
            ),
            (
                "e_sess_1",
                _ev(
                    event_type="session_terminate",
                    event_id="e_sess_1",
                    ts="2026-04-10T10:07:00Z",
                    monitor_id=mid(1),
                    actor_user="bob",
                    source_host=host(1),
                    source_country=country(1),
                    payload={"target_user": "bob", "method": "logout"},
                ),
            ),
            (
                "e_cmd_2",
                _ev(
                    event_type="command_executed",
                    event_id="e_cmd_2",
                    ts="2026-04-10T10:08:15Z",
                    monitor_id=mid(1),
                    actor_user="bob",
                    source_host=host(1),
                    source_country=country(1),
                    payload={
                        "command_line": "grep -R \"API_KEY\" /var/www --exclude-dir=node_modules",
                        "executed_command": 'grep -R "API_KEY" /var/www --exclude-dir=node_modules',
                    },
                ),
            ),
            (
                "e_passwd_1",
                _ev(
                    event_type="sensitive_file_access",
                    event_id="e_passwd_1",
                    ts="2026-04-10T10:09:30Z",
                    monitor_id=mid(1),
                    actor_user="bob",
                    source_host=host(1),
                    source_country=country(1),
                    payload={
                        "path": "/etc/passwd",
                        "command_line": "cat /etc/passwd",
                    },
                ),
            ),
            (
                "e_cmd_3",
                _ev(
                    event_type="command_executed",
                    event_id="e_cmd_3",
                    ts="2026-04-10T10:10:00Z",
                    monitor_id=mid(2),
                    actor_user="deploy",
                    source_host=host(2),
                    source_country=country(2),
                    payload={
                        "command_line": "python3 -m pip install -r requirements.txt",
                        "executed_command": "python3 -m pip install -r requirements.txt",
                    },
                ),
            ),
            (
                "e_wget_1",
                _ev(
                    event_type="tool_download",
                    event_id="e_wget_1",
                    ts="2026-04-10T10:11:45Z",
                    monitor_id=mid(2),
                    actor_user="deploy",
                    source_host=host(2),
                    source_country=country(2),
                    payload={
                        "channel": "wget",
                        "target": "https://cdn.example/bootstrap.sh",
                    },
                ),
            ),
            (
                "e_reboot_1",
                _ev(
                    event_type="host_reboot",
                    event_id="e_reboot_1",
                    ts="2026-04-10T10:12:50Z",
                    monitor_id=mid(2),
                    actor_user="system",
                    source_host=host(2),
                    source_country=country(2),
                    payload={"detail": "scheduled maintenance window (kernel upgrade)"},
                ),
            ),
            (
                "e_tamper_1",
                _ev(
                    event_type="tamper_attempt",
                    event_id="e_tamper_1",
                    ts="2026-04-10T10:14:00Z",
                    monitor_id=mid(0),
                    actor_user="alice",
                    source_host=host(0),
                    source_country=country(0),
                    payload={
                        "path": "/opt/risk_ctf/monitor/agent.py",
                        "observation": "mtime_or_size_changed",
                    },
                ),
            ),
            (
                "e_cmd_4",
                _ev(
                    event_type="command_executed",
                    event_id="e_cmd_4",
                    ts="2026-04-10T10:15:33Z",
                    monitor_id=mid(0),
                    actor_user="alice",
                    source_host=host(0),
                    source_country=country(0),
                    payload={
                        "command_line": "ls -la /etc/cron.d",
                        "executed_command": "ls -la /etc/cron.d",
                    },
                ),
            ),
        ]

        for _eid, envelope in events_spec:
            ledger.record_event(envelope)

        print(f"Demo ledger written: {db_path}")
        print("Monitors (assigned fictional nations):")
        for i, r in enumerate(regs):
            print(f"  {hosts[i][1]} -> {r['monitor_id']} @ {r['assigned_country']}")
        print(f"Events ingested: {len(events_spec)}")
        return 0
    finally:
        ledger.close()


if __name__ == "__main__":
    raise SystemExit(main())
