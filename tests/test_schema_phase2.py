"""Schema coverage for all ALLOWED_EVENT_TYPES and negative cases."""

from __future__ import annotations

import unittest

from risk_ctf.common.schema import ALLOWED_EVENT_TYPES, EventEnvelope, SchemaError


def _minimal_envelope(event_type: str) -> dict:
    common = {
        "event_id": "evt_x",
        "ts": "2026-03-23T20:00:00Z",
        "monitor_id": "mon_1",
        "actor_user": "alice",
        "source_host": "host1",
        "source_country": "Canada",
    }
    payloads: dict[str, dict] = {
        "user_login": {"source_ip": "10.0.0.1"},
        "sudo_elevation": {"method": "sudo"},
        "remote_login": {
            "destination_host": "dst",
            "destination_country": "Germany",
            "protocol": "ssh",
        },
        "command_executed": {"command_line": "whoami"},
        "tool_download": {"channel": "curl", "target": "https://x.example/y"},
        "host_reboot": {"detail": "system is rebooting"},
        "tamper_attempt": {"path": "/a/b.py", "observation": "size_changed"},
        "session_terminate": {"target_user": "bob"},
        "sensitive_file_access": {"path": "/etc/passwd", "command_line": "cat /etc/passwd"},
        "monitor_heartbeat": {},
    }
    return {"event_type": event_type, "payload": payloads[event_type], **common}


class SchemaPhase2Tests(unittest.TestCase):
    def test_every_allowed_event_type_validates(self) -> None:
        self.assertEqual(len(ALLOWED_EVENT_TYPES), 10)
        for et in sorted(ALLOWED_EVENT_TYPES):
            with self.subTest(event_type=et):
                env = _minimal_envelope(et)
                v = EventEnvelope.validate(env)
                self.assertEqual(v.event_type, et)

    def test_session_terminate_with_optional_method(self) -> None:
        env = _minimal_envelope("session_terminate")
        env["payload"]["method"] = "loginctl"
        self.assertEqual(EventEnvelope.validate(env).event_type, "session_terminate")

    def test_host_reboot_envelope(self) -> None:
        self.assertEqual(
            EventEnvelope.validate(_minimal_envelope("host_reboot")).event_type,
            "host_reboot",
        )

    def test_command_executed_rejects_empty_line(self) -> None:
        env = _minimal_envelope("command_executed")
        env["payload"]["command_line"] = "   "
        with self.assertRaises(SchemaError):
            EventEnvelope.validate(env)

    def test_command_executed_rejects_overlong_command(self) -> None:
        env = _minimal_envelope("command_executed")
        env["payload"]["command_line"] = "x" * 513
        with self.assertRaises(SchemaError):
            EventEnvelope.validate(env)


if __name__ == "__main__":
    unittest.main()
