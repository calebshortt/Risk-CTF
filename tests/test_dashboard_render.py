"""Dashboard HTML render smoke tests (enriched state)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from risk_ctf.common.schema import EventEnvelope
from risk_ctf.mothership.ledger import Ledger
from risk_ctf.mothership.server import render_dashboard_html
from risk_ctf.mothership.world_map import enrich_dashboard_state


class DashboardRenderTests(unittest.TestCase):
    def test_render_includes_map_and_feed_and_feed_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "ledger.db")
            ledger = Ledger(db)
            try:
                reg = ledger.register_monitor(
                    fingerprint="fp_dash",
                    source_host="h1",
                    source_country="Canada",
                    created_at_ts=1700000000,
                )
                mid = reg["monitor_id"]
                ev = EventEnvelope.validate(
                    {
                        "event_type": "user_login",
                        "event_id": "e1",
                        "ts": "2026-03-23T20:00:00Z",
                        "monitor_id": mid,
                        "actor_user": "player",
                        "source_host": "h1",
                        "source_country": "Canada",
                        "payload": {"source_ip": "127.0.0.1"},
                    }
                ).to_dict()
                ledger.record_event(ev)
                state = ledger.dashboard_state()
                enrich_dashboard_state(state)
                html = render_dashboard_html(state)
                self.assertIn("The Shattered Meridian", html)
                self.assertIn("activity-feed", html)
                self.assertIn("Recent activity", html)
                self.assertIn("world-svg", html)
            finally:
                ledger.close()


if __name__ == "__main__":
    unittest.main()
