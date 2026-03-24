"""SQLite-backed ledger for monitor registrations and events."""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Any

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
                SELECT actor_user, source_country, destination_country, event_type
                FROM events
                ORDER BY id ASC
                """
            ).fetchall()

        user_colors: dict[str, str] = {}
        country_users: dict[str, set[str]] = {}
        moves: list[dict[str, str]] = []
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
            if row["event_type"] == "remote_login" and row["destination_country"]:
                destination = str(row["destination_country"])
                country_users.setdefault(destination, set()).add(user)
                moves.append(
                    {
                        "user": user,
                        "from": source,
                        "to": destination,
                        "color": user_colors[user],
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
        return {"user_colors": user_colors, "countries": countries, "moves": moves}

