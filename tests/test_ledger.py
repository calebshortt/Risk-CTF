from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from risk_ctf.common.schema import EventEnvelope
from risk_ctf.mothership.ledger import Ledger


class LedgerTests(unittest.TestCase):
    def test_register_and_secret_lookup(self) -> None:
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
                secret = ledger.get_monitor_secret(reg["monitor_id"])
                self.assertEqual(secret, reg["auth_secret"])
            finally:
                ledger.close()

    def test_nonce_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "ledger.db")
            ledger = Ledger(db)
            try:
                ledger.remember_nonce("m1", "n1", 1700000000, 300)
                self.assertTrue(ledger.nonce_seen("m1", "n1"))
            finally:
                ledger.close()

    def test_record_event_does_not_store_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "ledger.db")
            ledger = Ledger(db)
            try:
                reg = ledger.register_monitor(
                    fingerprint="fp_hb_skip",
                    source_host="h1",
                    source_country="Canada",
                    created_at_ts=1700000000,
                )
                mid = reg["monitor_id"]
                hb = EventEnvelope.validate(
                    {
                        "event_type": "monitor_heartbeat",
                        "event_id": "hb_evt_1",
                        "ts": "2026-03-23T20:00:00Z",
                        "monitor_id": mid,
                        "actor_user": "alice",
                        "source_host": "h1",
                        "source_country": reg["assigned_country"],
                        "payload": {},
                    }
                ).to_dict()
                ledger.record_event(hb)
                with ledger._lock:
                    cnt = ledger._conn.execute(
                        "SELECT COUNT(*) AS c FROM events WHERE event_type = 'monitor_heartbeat'"
                    ).fetchone()["c"]
                self.assertEqual(int(cnt), 0)
            finally:
                ledger.close()

    def test_dashboard_state_has_phase2_feed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "ledger.db")
            ledger = Ledger(db)
            try:
                state = ledger.dashboard_state()
                self.assertIn("activity_feed", state)
                self.assertIn("players_legend", state)
                self.assertIsInstance(state["activity_feed"], list)
            finally:
                ledger.close()


if __name__ == "__main__":
    unittest.main()

