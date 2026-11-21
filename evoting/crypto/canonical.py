"""Serialización canónica (RFC 8785, JCS) y hash."""
from __future__ import annotations

import hashlib

import rfc8785


def canonical_bytes(obj) -> bytes:
    return rfc8785.dumps(obj)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
