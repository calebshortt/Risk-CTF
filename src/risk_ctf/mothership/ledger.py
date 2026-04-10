"""SQLite-backed ledger for monitor registrations and events."""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Any


_ACTIVITY_SUMMARY_MAX = 512


def _executed_command_text(payload: dict[str, Any]) -> str:
    return str(payload.get("executed_command") or payload.get("command_line", ""))[
        :_ACTIVITY_SUMMARY_MAX
    ]


def _parse_payload_json(raw: Any) -> dict[str, Any]:
    if raw is None or raw == "":
        return {}
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    return obj if isinstance(obj, dict) else {}


def _command_text_for_event(event_type: str, payload: dict[str, Any]) -> str:
    """Human-readable command / invocation line for dashboard columns."""
    if event_type == "command_executed":
        return _executed_command_text(payload).strip()
    if event_type == "sensitive_file_access":
        return str(payload.get("command_line", "")).strip()[:_ACTIVITY_SUMMARY_MAX]
    if event_type == "tool_download":
        return (
            f"{payload.get('channel', '?')}: {payload.get('target', '')}".strip()
        )[:_ACTIVITY_SUMMARY_MAX]
    if event_type == "remote_login":
        host = str(payload.get("destination_host", "")).strip()
        proto = str(payload.get("protocol", "ssh")).strip()
        if host:
            return f"{proto} {host}"[:_ACTIVITY_SUMMARY_MAX]
        return ""
    return ""


def _activity_feed_summary(event_type: str, payload: dict[str, Any]) -> str:
    if event_type == "command_executed":
        return _executed_command_text(payload)
    if event_type == "sensitive_file_access":
        return str(payload.get("command_line", ""))[:_ACTIVITY_SUMMARY_MAX]
    if event_type == "tool_download":
        return f"{payload.get('channel', '?')}: {payload.get('target', '')}"[
            :_ACTIVITY_SUMMARY_MAX
        ]
    if event_type == "host_reboot":
        return str(payload.get("detail", ""))[:_ACTIVITY_SUMMARY_MAX]
    if event_type == "tamper_attempt":
        return f"{payload.get('path', '')}: {payload.get('observation', '')}"[:_ACTIVITY_SUMMARY_MAX]
    if event_type == "session_terminate":
        return f"target={payload.get('target_user')} via {payload.get('method', '')}"[
            :_ACTIVITY_SUMMARY_MAX
        ]
    if event_type == "remote_login":
        return (
            f"ssh {payload.get('destination_host', '')} "
            f"({payload.get('destination_country', '')})"
        )[:_ACTIVITY_SUMMARY_MAX]
    if event_type == "user_login":
        return f"login ip={payload.get('source_ip', '')}"[:_ACTIVITY_SUMMARY_MAX]
    if event_type == "sudo_elevation":
        return str(payload.get("method", ""))[:_ACTIVITY_SUMMARY_MAX]
    if event_type == "monitor_heartbeat":
        return "monitor alive"
    return str(event_type)[:_ACTIVITY_SUMMARY_MAX]


COUNTRIES = [
    "Canada",
    "United_States",
    "Mexico",
    "Brazil",
    "United_Kingdom",
    "Germany",
    "Nigeria",
    "India",
    "Japan",
    "Australia",
]


class Ledger:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # ThreadingHTTPServer dispatches each request on a worker thread; one connection must be
        # shared with check_same_thread=False and explicit locking for correctness.
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._init_db()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _init_db(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS monitors (
                monitor_id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                source_host TEXT NOT NULL,
                source_country TEXT NOT NULL,
                auth_secret TEXT NOT NULL,
                assigned_country TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                monitor_id TEXT NOT NULL,
                actor_user TEXT NOT NULL,
                event_type TEXT NOT NULL,
                ts TEXT NOT NULL,
                source_country TEXT NOT NULL,
                destination_country TEXT,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS nonces (
                monitor_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                ts INTEGER NOT NULL,
                PRIMARY KEY (monitor_id, nonce)
            );
            """
        )
        self._conn.commit()

    def register_monitor(
        self,
        fingerprint: str,
        source_host: str,
        source_country: str,
        created_at_ts: int,
    ) -> dict[str, str]:
        with self._lock:
            existing = self._conn.execute(
                "SELECT monitor_id, auth_secret, assigned_country FROM monitors WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if existing:
                return {
                    "monitor_id": existing["monitor_id"],
                    "auth_secret": existing["auth_secret"],
                    "assigned_country": existing["assigned_country"],
                }

            used = {
                row["assigned_country"]
                for row in self._conn.execute("SELECT assigned_country FROM monitors").fetchall()
            }
            available = [c for c in COUNTRIES if c not in used]
            assigned_country = available[0] if available else COUNTRIES[len(used) % len(COUNTRIES)]
            monitor_id = f"mon_{secrets.token_hex(8)}"
            auth_secret = secrets.token_urlsafe(32)
            self._conn.execute(
                """
                INSERT INTO monitors (
                    monitor_id, fingerprint, source_host, source_country, auth_secret, assigned_country, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    monitor_id,
                    fingerprint,
                    source_host,
                    source_country,
                    auth_secret,
                    assigned_country,
                    created_at_ts,
                ),
            )
            self._conn.commit()
            return {
                "monitor_id": monitor_id,
                "auth_secret": auth_secret,
                "assigned_country": assigned_country,
            }

    def get_monitor_secret(self, monitor_id: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT auth_secret FROM monitors WHERE monitor_id = ?",
                (monitor_id,),
            ).fetchone()
        if not row:
            return None
        return str(row["auth_secret"])

    def nonce_seen(self, monitor_id: str, nonce: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM nonces WHERE monitor_id = ? AND nonce = ?",
                (monitor_id, nonce),
            ).fetchone()
        return row is not None

    def remember_nonce(self, monitor_id: str, nonce: str, ts: int, nonce_ttl: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO nonces (monitor_id, nonce, ts) VALUES (?, ?, ?)",
                (monitor_id, nonce, ts),
            )
            self._conn.execute(
                "DELETE FROM nonces WHERE ts < ?",
                (ts - nonce_ttl,),
            )
            self._conn.commit()

    def record_event(self, event: dict[str, Any]) -> None:
        # Heartbeats carry no host activity; omit from the ledger so the dashboard only reflects
        # real events (nonce is still recorded by the API handler before ingest).
        if event.get("event_type") == "monitor_heartbeat":
            return
        payload = event["payload"]
        destination_country = payload.get("destination_country")
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO events (
                    event_id, monitor_id, actor_user, event_type, ts, source_country, destination_country, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_id"],
                    event["monitor_id"],
                    event["actor_user"],
                    event["event_type"],
                    event["ts"],
                    event["source_country"],
                    destination_country,
                    json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
                ),
            )
            self._conn.commit()

    def dashboard_state(self) -> dict[str, Any]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT actor_user, source_country, destination_country, event_type, payload_json
                FROM events
                WHERE event_type != 'monitor_heartbeat'
                ORDER BY id ASC
                """
            ).fetchall()

        user_colors: dict[str, str] = {}
        country_users: dict[str, set[str]] = {}
        moves: list[dict[str, Any]] = []
        color_pool = [
            "#ff006e",
            "#3a86ff",
            "#ffbe0b",
            "#8338ec",
            "#2ec4b6",
            "#fb5607",
            "#06d6a0",
        ]

        for row in rows:
            user = str(row["actor_user"])
            if user not in user_colors:
                user_colors[user] = color_pool[len(user_colors) % len(color_pool)]

            source = str(row["source_country"])
            country_users.setdefault(source, set()).add(user)
            payload = _parse_payload_json(row["payload_json"])
            et = str(row["event_type"])
            if et == "remote_login" and row["destination_country"]:
                destination = str(row["destination_country"])
                country_users.setdefault(destination, set()).add(user)
                cmd = _command_text_for_event("remote_login", payload)
                moves.append(
                    {
                        "user": user,
                        "from": source,
                        "to": destination,
                        "color": user_colors[user],
                        "kind": "remote",
                        "command": cmd,
                    }
                )
            elif et == "command_executed":
                cmd = _command_text_for_event("command_executed", payload)
                if cmd:
                    moves.append(
                        {
                            "user": user,
                            "from": source,
                            "to": source,
                            "color": user_colors[user],
                            "kind": "command",
                            "command": cmd,
                        }
                    )

        countries = [
            {
                "country": country,
                "users": sorted(list(users)),
                "colors": [user_colors[u] for u in sorted(list(users))],
            }
            for country, users in sorted(country_users.items())
        ]
        players_legend = [
            {"label": user, "color": user_colors[user]} for user in sorted(user_colors.keys())
        ]
        activity_feed = self._recent_activity_rows(48)
        return {
            "user_colors": user_colors,
            "countries": countries,
            "moves": moves,
            "players_legend": players_legend,
            "activity_feed": activity_feed,
        }

    def _recent_activity_rows(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT event_type, actor_user, source_country, payload_json, ts
                FROM events
                WHERE event_type != 'monitor_heartbeat'
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            payload = _parse_payload_json(row["payload_json"])
            et = str(row["event_type"])
            cmd_text = _command_text_for_event(et, payload)
            # Summary column: prefer the command / invocation observed on the host.
            summary = (
                cmd_text.strip()
                if cmd_text.strip()
                else _activity_feed_summary(et, payload)
            )
            out.append(
                {
                    "event_type": et,
                    "actor_user": row["actor_user"],
                    "source_country": row["source_country"],
                    "ts": row["ts"],
                    "summary": summary,
                    "command_text": cmd_text,
                    "executed_command": _executed_command_text(payload)
                    if et == "command_executed"
                    else "",
                }
            )
        return out

