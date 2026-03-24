from __future__ import annotations

import unittest

from risk_ctf.common.auth import sign_request, verify_signature


class AuthTests(unittest.TestCase):
    def test_sign_and_verify_round_trip(self) -> None:
        payload = {"a": 1, "b": "x"}
        sig = sign_request(
            secret="secret123",
            method="POST",
            path="/api/v1/events",
            payload=payload,
            ts=1700000000,
            nonce="abc",
        )
        self.assertTrue(
            verify_signature(
                secret="secret123",
                method="POST",
                path="/api/v1/events",
                payload=payload,
                ts=1700000000,
                nonce="abc",
                signature_b64=sig,
            )
        )

    def test_signature_rejects_tampered_payload(self) -> None:
        sig = sign_request(
            secret="secret123",
            method="POST",
            path="/api/v1/events",
            payload={"a": 1},
            ts=1700000000,
            nonce="abc",
        )
        self.assertFalse(
            verify_signature(
                secret="secret123",
                method="POST",
                path="/api/v1/events",
                payload={"a": 2},
                ts=1700000000,
                nonce="abc",
                signature_b64=sig,
            )
        )


if __name__ == "__main__":
    unittest.main()

