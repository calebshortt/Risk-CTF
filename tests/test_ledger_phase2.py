"""Ledger dashboard_state Phase 2 fields (activity_feed, players_legend)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from risk_ctf.common.schema import EventEnvelope
from risk_ctf.mothership.ledger import Ledger


class LedgerPhase2Tests(unittest.TestCase):
    def test_activity_feed_newest_first_and_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "ledger.db")
            ledger = Ledger(db)
            try:
                reg = ledger.register_monitor(
                    fingerprint="fp_feed",
                    source_host="h1",
                    source_country="Canada",
                    created_at_ts=1700000000,
                )
                mid = reg["monitor_id"]
                e1 = EventEnvelope.validate(
                    {
                        "event_type": "command_executed",
                        "event_id": "e1",
                        "ts": "2026-03-23T20:00:00Z",
                        "monitor_id": mid,
                        "actor_user": "u1",
                        "source_host": "h1",
                        "source_country": "Canada",
                        "payload": {"command_line": "ls"},
                    }
                ).to_dict()
                e2 = EventEnvelope.validate(
                    {
                        "event_type": "tool_download",
                        "event_id": "e2",
                        "ts": "2026-03-23T20:00:01Z",
                        "monitor_id": mid,
                        "actor_user": "u2",
                        "source_host": "h1",
                        "source_country": "Canada",
                        "payload": {"channel": "wget", "target": "http://a/b"},
                    }
                ).to_dict()
                ledger.record_event(e1)
                ledger.record_event(e2)
                state = ledger.dashboard_state()
                feed = state["activity_feed"]
                self.assertGreaterEqual(len(feed), 2)
                self.assertEqual(feed[0]["event_type"], "tool_download")
                self.assertEqual(feed[1]["event_type"], "command_executed")
                self.assertIn("wget", feed[0]["summary"])
                self.assertIn("ls", feed[1]["summary"])
                self.assertEqual(feed[1].get("executed_command"), "ls")
                self.assertEqual(feed[1].get("command_text"), "ls")
                legend = state["players_legend"]
                labels = {x["label"] for x in legend}
                self.assertIn("u1", labels)
                self.assertIn("u2", labels)
            finally:
                ledger.close()

    def test_activity_feed_omits_heartbeat_so_commands_remain_visible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "ledger.db")
            ledger = Ledger(db)
            try:
                reg = ledger.register_monitor(
                    fingerprint="fp_hb",
                    source_host="h1",
                    source_country="Canada",
                    created_at_ts=1700000000,
                )
                mid = reg["monitor_id"]
                hb = EventEnvelope.validate(
                    {
                        "event_type": "monitor_heartbeat",
                        "event_id": "hb1",
                        "ts": "2026-03-23T20:00:00Z",
                        "monitor_id": mid,
                        "actor_user": "sys",
                        "source_host": "h1",
                        "source_country": "Canada",
                        "payload": {},
                    }
                ).to_dict()
                cmd = EventEnvelope.validate(
                    {
                        "event_type": "command_executed",
                        "event_id": "c1",
                        "ts": "2026-03-23T20:00:01Z",
                        "monitor_id": mid,
                        "actor_user": "u1",
                        "source_host": "h1",
                        "source_country": "Canada",
                        "payload": {"command_line": "whoami", "executed_command": "whoami"},
                    }
                ).to_dict()
                for _ in range(50):
                    hb2 = dict(hb)
                    hb2["event_id"] = f"hb_{_}"
                    hb2["ts"] = f"2026-03-23T20:01:{_:02d}Z"
                    ledger.record_event(hb2)
                ledger.record_event(cmd)
                feed = ledger.dashboard_state()["activity_feed"]
                self.assertTrue(any(f.get("event_type") == "command_executed" for f in feed))
                self.assertFalse(any(f.get("event_type") == "monitor_heartbeat" for f in feed))
            finally:
                ledger.close()


if __name__ == "__main__":
    unittest.main()
