"""Tokens de un solo uso autenticados con HMAC-SHA256 (emitidos por la autoridad)."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

from evoting.crypto.canonical import canonical_bytes

VERSION = "v1"
_KEYS = {"version", "election_id", "token_id", "secret", "tag"}
_HEX = {"token_id": re.compile(r"[0-9a-f]{32}"), "secret": re.compile(r"[0-9a-f]{64}"),
        "tag": re.compile(r"[0-9a-f]{64}"), "election_id": re.compile(r"[0-9a-f]{16}")}


@dataclass(frozen=True)
class Token:
    election_id: str
    token_id: str
    secret: str
    tag: str

    def to_dict(self) -> dict[str, str]:
        return {"version": VERSION, "election_id": self.election_id,
                "token_id": self.token_id, "secret": self.secret, "tag": self.tag}

    @staticmethod
    def from_dict(d) -> "Token":
        if not isinstance(d, dict) or set(d) != _KEYS:
            raise ValueError("Token con claves inválidas")
        if d["version"] != VERSION:
            raise ValueError("Versión de token no soportada")
        for k, rx in _HEX.items():
            if not isinstance(d[k], str) or rx.fullmatch(d[k]) is None:
                raise ValueError(f"Campo de token inválido: {k}")
        return Token(d["election_id"], d["token_id"], d["secret"], d["tag"])


def _tag(key: bytes, election_id: str, token_id: str, secret: str) -> str:
    msg = canonical_bytes({"election_id": election_id, "token_id": token_id, "secret": secret})
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def issue_token(key: bytes, election_id: str) -> Token:
    token_id = secrets.token_hex(16)
    secret = secrets.token_hex(32)
    return Token(election_id, token_id, secret, _tag(key, election_id, token_id, secret))


def verify_token(key: bytes, token: Token) -> bool:
    expected = _tag(key, token.election_id, token.token_id, token.secret)
    return hmac.compare_digest(expected.encode(), str(token.tag).encode())
