"""Mothership registration and event submission client."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import ssl
import urllib.request
import uuid
from typing import Any

from risk_ctf.common.auth import create_nonce, sign_request, unix_ts
from risk_ctf.common.contracts import (
    EVENTS_PATH,
    HEADER_MONITOR_ID,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TS,
    REGISTER_PATH,
)


@dataclass
class MonitorState:
    monitor_id: str
    auth_secret: str
    assigned_country: str
    source_host: str


class MonitorClient:
    def __init__(self, base_url: str, state_file: str, allow_insecure_dev_tls: bool = False) -> None:
        self._base_url = base_url.rstrip("/")
        self._state_file = Path(state_file)
        self._ctx = ssl.create_default_context()
        if allow_insecure_dev_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _post_json(self, path: str, body: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
        data = json.dumps(body, ensure_ascii=True).encode("utf-8")
        req = urllib.request.Request(
            f"{self._base_url}{path}",
            data=data,
            method="POST",
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        with urllib.request.urlopen(req, context=self._ctx, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def load_state(self) -> MonitorState | None:
        if not self._state_file.exists():
            return None
        raw = json.loads(self._state_file.read_text(encoding="utf-8"))
        return MonitorState(
            monitor_id=raw["monitor_id"],
            auth_secret=raw["auth_secret"],
            assigned_country=raw["assigned_country"],
            source_host=raw["source_host"],
        )

    def _save_state(self, state: MonitorState) -> None:
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state_file.write_text(
            json.dumps(
                {
                    "monitor_id": state.monitor_id,
                    "auth_secret": state.auth_secret,
                    "assigned_country": state.assigned_country,
                    "source_host": state.source_host,
                },
                ensure_ascii=True,
                indent=2,
            ),
            encoding="utf-8",
        )
        if os.name == "posix":
            os.chmod(self._state_file, 0o600)

    def register(self, source_host: str, source_country: str) -> MonitorState:
        fingerprint = str(uuid.uuid5(uuid.NAMESPACE_DNS, source_host))
        payload = {
            "fingerprint": fingerprint,
            "source_host": source_host,
            "source_country": source_country,
        }
        raw = self._post_json(REGISTER_PATH, payload)
        state = MonitorState(
            monitor_id=raw["monitor_id"],
            auth_secret=raw["auth_secret"],
            assigned_country=raw["assigned_country"],
            source_host=source_host,
        )
        self._save_state(state)
        return state

    def send_event(self, state: MonitorState, event: dict[str, Any]) -> dict[str, Any]:
        ts = unix_ts()
        nonce = create_nonce()
        signature = sign_request(
            secret=state.auth_secret,
            method="POST",
            path=EVENTS_PATH,
            payload=event,
            ts=ts,
            nonce=nonce,
        )
        headers = {
            HEADER_MONITOR_ID: state.monitor_id,
            HEADER_TS: str(ts),
            HEADER_NONCE: nonce,
            HEADER_SIGNATURE: signature,
        }
        return self._post_json(EVENTS_PATH, event, headers=headers)

