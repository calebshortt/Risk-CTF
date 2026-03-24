from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from risk_ctf.mothership.ledger import COUNTRIES, Ledger
from risk_ctf.mothership.world_map import STARTING_PLAYERS, enrich_dashboard_state


class WorldMapTests(unittest.TestCase):
    def test_enrich_has_ten_nations_two_players_opposite_sides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(str(Path(tmp) / "db.sqlite"))
            try:
                state = ledger.dashboard_state()
                enrich_dashboard_state(state)
                world = state["world"]
                self.assertEqual(len(world["nations"]), 10)
                self.assertEqual(len(COUNTRIES), 10)
                for i, n in enumerate(world["nations"]):
                    self.assertEqual(n["key"], COUNTRIES[i])
                    self.assertEqual(n["host_index"], i + 1)
                self.assertEqual(len(world["players"]), 2)
                self.assertEqual(world["players"][0]["nation_key"], "Canada")
                self.assertEqual(world["players"][1]["nation_key"], "Australia")
                self.assertEqual(world["nations"][0]["side"], "west")
                self.assertEqual(world["nations"][9]["side"], "east")
                self.assertEqual(len(STARTING_PLAYERS), 2)
            finally:
                ledger.close()


if __name__ == "__main__":
    unittest.main()
