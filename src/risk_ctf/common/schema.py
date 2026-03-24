"""Canonical schemas and strict validation for Risk-CTF events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import json
import re

ALLOWED_EVENT_TYPES = {"user_login", "sudo_elevation", "remote_login"}
ENTITY_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")


class SchemaError(ValueError):
    """Raised for malformed envelopes or payloads."""


def now_utc_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _require_entity(name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise SchemaError(f"{name} must be a string")
    if not ENTITY_RE.fullmatch(value):
        raise SchemaError(f"{name} contains invalid characters")
    return value


def _require_ts(name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise SchemaError(f"{name} must be a string timestamp")
    parsed = value.replace("Z", "+00:00")
    try:
        datetime.fromisoformat(parsed)
    except ValueError as exc:
        raise SchemaError(f"{name} must be ISO-8601") from exc
    return value


@dataclass(frozen=True)
class EventEnvelope:
    event_type: str
    event_id: str
    ts: str
    monitor_id: str
    actor_user: str
    source_host: str
    source_country: str
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "event_id": self.event_id,
            "ts": self.ts,
            "monitor_id": self.monitor_id,
            "actor_user": self.actor_user,
            "source_host": self.source_host,
            "source_country": self.source_country,
            "payload": self.payload,
        }

    @staticmethod
    def validate(data: dict[str, Any]) -> "EventEnvelope":
        if not isinstance(data, dict):
            raise SchemaError("envelope must be a JSON object")
        event_type = data.get("event_type")
        if event_type not in ALLOWED_EVENT_TYPES:
            raise SchemaError("event_type is unsupported")
        event_id = _require_entity("event_id", data.get("event_id"))
        ts = _require_ts("ts", data.get("ts"))
        monitor_id = _require_entity("monitor_id", data.get("monitor_id"))
        actor_user = _require_entity("actor_user", data.get("actor_user"))
        source_host = _require_entity("source_host", data.get("source_host"))
        source_country = _require_entity("source_country", data.get("source_country"))
        payload = data.get("payload")
        if not isinstance(payload, dict):
            raise SchemaError("payload must be an object")

        if event_type == "remote_login":
            _require_entity("payload.destination_host", payload.get("destination_host"))
            _require_entity(
                "payload.destination_country",
                payload.get("destination_country"),
            )
            _require_entity("payload.protocol", payload.get("protocol"))

        return EventEnvelope(
            event_type=event_type,
            event_id=event_id,
            ts=ts,
            monitor_id=monitor_id,
            actor_user=actor_user,
            source_host=source_host,
            source_country=source_country,
            payload=payload,
        )

