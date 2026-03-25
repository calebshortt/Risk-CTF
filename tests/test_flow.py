from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from risk_ctf.common.schema import EventEnvelope
from risk_ctf.mothership.ledger import Ledger


class FlowTests(unittest.TestCase):
    def test_register_ingest_dashboard_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "ledger.db")
            ledger = Ledger(db)
            try:
                reg = ledger.register_monitor(
                    fingerprint="fp_1",
                    source_host="host1",
                    source_country="Canada",
                    created_at_ts=1700000000,
                )
                event = EventEnvelope.validate(
                    {
                        "event_type": "remote_login",
                        "event_id": "evt_abc",
                        "ts": "2026-03-23T20:00:00Z",
                        "monitor_id": reg["monitor_id"],
                        "actor_user": "alice",
                        "source_host": "host1",
                        "source_country": "Canada",
                        "payload": {
                            "destination_host": "host2",
                            "destination_country": "Germany",
                            "protocol": "ssh",
                        },
                    }
                ).to_dict()
                ledger.record_event(event)
                state = ledger.dashboard_state()
                self.assertIn("alice", state["user_colors"])
                self.assertTrue(any(m["to"] == "Germany" for m in state["moves"]))
                self.assertIn("activity_feed", state)
                self.assertIn("players_legend", state)
                self.assertTrue(any(f.get("event_type") == "remote_login" for f in state["activity_feed"]))

                cmd = EventEnvelope.validate(
                    {
                        "event_type": "command_executed",
                        "event_id": "evt_cmd",
                        "ts": "2026-03-23T21:00:00Z",
                        "monitor_id": reg["monitor_id"],
                        "actor_user": "alice",
                        "source_host": "host1",
                        "source_country": "Canada",
                        "payload": {"command_line": "id"},
                    }
                ).to_dict()
                ledger.record_event(cmd)
                state2 = ledger.dashboard_state()
                self.assertTrue(any(f.get("event_type") == "command_executed" for f in state2["activity_feed"]))
            finally:
                ledger.close()


if __name__ == "__main__":
    unittest.main()

