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


if __name__ == "__main__":
    unittest.main()

