"""tools/gen_dev_certs.py — optional cryptography dependency."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


class GenDevCertsTests(unittest.TestCase):
    def test_script_writes_pem_pair_when_cryptography_available(self) -> None:
        script = _repo_root() / "tools" / "gen_dev_certs.py"
        self.assertTrue(script.is_file(), "tools/gen_dev_certs.py must exist")
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography not installed; pip install -e '.[dev]'")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            r = subprocess.run(
                [sys.executable, str(script), "--output-dir", str(out)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(r.returncode, 0, msg=r.stderr + r.stdout)
            self.assertTrue((out / "cert.pem").is_file())
            self.assertTrue((out / "key.pem").is_file())
            self.assertGreater((out / "cert.pem").stat().st_size, 100)


if __name__ == "__main__":
    unittest.main()
