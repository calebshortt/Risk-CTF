from __future__ import annotations

import unittest

from risk_ctf.common.schema import EventEnvelope, SchemaError


class SchemaTests(unittest.TestCase):
    def test_valid_remote_login_envelope(self) -> None:
        envelope = {
            "event_type": "remote_login",
            "event_id": "evt_1",
            "ts": "2026-03-23T20:00:00Z",
            "monitor_id": "mon_1",
            "actor_user": "alice",
            "source_host": "host1",
            "source_country": "Canada",
            "payload": {
                "destination_host": "host2",
                "destination_country": "Germany",
                "protocol": "ssh",
            },
        }
        validated = EventEnvelope.validate(envelope)
        self.assertEqual(validated.event_type, "remote_login")

    def test_invalid_event_type(self) -> None:
        envelope = {
            "event_type": "bad",
            "event_id": "evt_1",
            "ts": "2026-03-23T20:00:00Z",
            "monitor_id": "mon_1",
            "actor_user": "alice",
            "source_host": "host1",
            "source_country": "Canada",
            "payload": {},
        }
        with self.assertRaises(SchemaError):
            EventEnvelope.validate(envelope)

    def test_command_executed_envelope(self) -> None:
        envelope = {
            "event_type": "command_executed",
            "event_id": "evt_c",
            "ts": "2026-03-23T20:00:00Z",
            "monitor_id": "mon_1",
            "actor_user": "bob",
            "source_host": "host1",
            "source_country": "Canada",
            "payload": {"command_line": "ls -la"},
        }
        self.assertEqual(EventEnvelope.validate(envelope).event_type, "command_executed")

    def test_tool_download_envelope(self) -> None:
        envelope = {
            "event_type": "tool_download",
            "event_id": "evt_d",
            "ts": "2026-03-23T20:00:00Z",
            "monitor_id": "mon_1",
            "actor_user": "bob",
            "source_host": "host1",
            "source_country": "Canada",
            "payload": {"channel": "curl", "target": "https://example.com/a.zip"},
        }
        self.assertEqual(EventEnvelope.validate(envelope).event_type, "tool_download")

    def test_tamper_attempt_envelope(self) -> None:
        envelope = {
            "event_type": "tamper_attempt",
            "event_id": "evt_t",
            "ts": "2026-03-23T20:00:00Z",
            "monitor_id": "mon_1",
            "actor_user": "unknown",
            "source_host": "host1",
            "source_country": "Canada",
            "payload": {
                "path": "/opt/risk_ctf/monitor/agent.py",
                "observation": "mtime_or_size_changed",
            },
        }
        self.assertEqual(EventEnvelope.validate(envelope).event_type, "tamper_attempt")


if __name__ == "__main__":
    unittest.main()

