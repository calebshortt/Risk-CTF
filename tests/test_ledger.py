from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()

