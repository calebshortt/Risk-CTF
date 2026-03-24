"""Authentication and request-signing helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Any

from risk_ctf.common.schema import canonical_json_bytes


def create_secret() -> str:
    return secrets.token_urlsafe(32)


def create_nonce() -> str:
    return secrets.token_urlsafe(16)


def unix_ts() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp())


def body_sha256_base64(payload: dict[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json_bytes(payload)).digest()
    return base64.b64encode(digest).decode("ascii")


def signature_input(method: str, path: str, body_sha: str, ts: int, nonce: str) -> bytes:
    canonical = "\n".join(
        [
            method.upper(),
            path,
            body_sha,
            str(ts),
            nonce,
        ]
    )
    return canonical.encode("utf-8")


def sign_request(
    secret: str,
    method: str,
    path: str,
    payload: dict[str, Any],
    ts: int,
    nonce: str,
) -> str:
    body_sha = body_sha256_base64(payload)
    msg = signature_input(method=method, path=path, body_sha=body_sha, ts=ts, nonce=nonce)
    digest = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def verify_signature(
    secret: str,
    method: str,
    path: str,
    payload: dict[str, Any],
    ts: int,
    nonce: str,
    signature_b64: str,
) -> bool:
    expected = sign_request(
        secret=secret,
        method=method,
        path=path,
        payload=payload,
        ts=ts,
        nonce=nonce,
    )
    return hmac.compare_digest(expected, signature_b64)

