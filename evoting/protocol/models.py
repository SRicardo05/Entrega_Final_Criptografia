"""Modelos versionados (v1) del protocolo y validación estricta de forma."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from evoting.crypto.canonical import canonical_bytes, sha256_hex
from evoting.crypto.elgamal import Ciphertext
from evoting.crypto.group import GROUP_ID, IDENTITY, G, Point
from evoting.crypto.or_proof import ORProof
from evoting.crypto.tokens import Token

VERSION = "v1"
_PROOF_KEYS = {"A0", "B0", "A1", "B1", "c0", "c1", "s0", "s1"}
_H64 = re.compile(r"[0-9a-f]{64}")
_H32 = re.compile(r"[0-9a-f]{32}")
_H16 = re.compile(r"[0-9a-f]{16}")
_H128 = re.compile(r"[0-9a-f]{128}")


class MalformedBallot(ValueError):
    """La papeleta no tiene la forma esperada."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _keys(d, keys, what: str) -> None:
    if not isinstance(d, dict):
        raise MalformedBallot(f"{what}: se esperaba un objeto")
    if set(d) != set(keys):
        raise MalformedBallot(f"{what}: claves inesperadas o faltantes")


def _hex(d, k, rx, what: str) -> None:
    v = d[k]
    if not isinstance(v, str) or rx.fullmatch(v) is None:
        raise MalformedBallot(f"{what}.{k}: hex inválido")


def _check_shape(d, id_key: str) -> None:
    top = {"version", "election_id", "group_id", id_key, "ciphertext", "proof", "timestamp"}
    _keys(d, top, "papeleta")
    for k, v in d.items():
        if k not in ("token", "ciphertext", "proof") and not isinstance(v, str):
            raise MalformedBallot(f"papeleta.{k}: se esperaba str")
    if d["version"] != VERSION:
        raise MalformedBallot("Versión no soportada")
    if d["group_id"] != GROUP_ID:
        raise MalformedBallot("Grupo no soportado")
    _hex(d, "election_id", _H16, "papeleta")
    if not d["timestamp"]:
        raise MalformedBallot("papeleta.timestamp vacío")
    if id_key == "token":
        t = d["token"]
        _keys(t, {"version", "election_id", "token_id", "secret", "tag"}, "token")
        for k, v in t.items():
            if not isinstance(v, str):
                raise MalformedBallot(f"token.{k}: se esperaba str")
        if t["version"] != VERSION:
            raise MalformedBallot("Versión de token no soportada")
        _hex(t, "election_id", _H16, "token")
        _hex(t, "token_id", _H32, "token")
        _hex(t, "secret", _H64, "token")
        _hex(t, "tag", _H64, "token")
    else:
        _hex(d, "token_id", _H32, "papeleta")
    ct = d["ciphertext"]
    _keys(ct, {"alpha", "beta"}, "ciphertext")
    for k in ("alpha", "beta"):
        _hex(ct, k, _H64, "ciphertext")
    pr = d["proof"]
    _keys(pr, _PROOF_KEYS, "proof")
    for k in _PROOF_KEYS:
        _hex(pr, k, _H64, "proof")


def check_ballot_shape(d) -> None:
    _check_shape(d, "token")


def check_published_shape(d) -> None:
    _check_shape(d, "token_id")


def _ct_dict(ct: Ciphertext) -> dict[str, str]:
    return {"alpha": ct.alpha.to_hex(), "beta": ct.beta.to_hex()}


def _ct_from(d) -> Ciphertext:
    return Ciphertext(Point.from_hex(d["alpha"]), Point.from_hex(d["beta"]))


def ciphertext_hash(ct: Ciphertext) -> str:
    return sha256_hex(canonical_bytes(_ct_dict(ct)))


@dataclass(frozen=True)
class PublicParams:
    election_id: str
    question: str
    n_max: int
    h: Point
    verify_key: str

    def to_dict(self) -> dict:
        return {"version": VERSION, "election_id": self.election_id, "group_id": GROUP_ID,
                "generator": G.to_hex(), "public_key": self.h.to_hex(),
                "n_max_voters": self.n_max, "allowed_options": [0, 1],
                "question": self.question, "authority_verify_key": self.verify_key}

    @staticmethod
    def from_dict(d) -> "PublicParams":
        keys = {"version", "election_id", "group_id", "generator", "public_key",
                "n_max_voters", "allowed_options", "question", "authority_verify_key"}
        if not isinstance(d, dict) or set(d) != keys:
            raise ValueError("Parámetros públicos con claves inválidas")
        if d["version"] != VERSION:
            raise ValueError("Versión de parámetros no soportada")
        if d["group_id"] != GROUP_ID:
            raise ValueError("Grupo no soportado")
        if d["generator"] != G.to_hex():
            raise ValueError("Generador distinto del esperado")
        n = d["n_max_voters"]
        if not _is_int(n) or not 1 <= n <= 20:
            raise ValueError("n_max_voters debe estar entre 1 y 20")
        ao = d["allowed_options"]
        if not isinstance(ao, list) or len(ao) != 2 or not all(_is_int(x) for x in ao) or ao != [0, 1]:
            raise ValueError("allowed_options debe ser [0, 1]")
        for k, rx in (("election_id", _H16), ("authority_verify_key", _H64)):
            if not isinstance(d[k], str) or rx.fullmatch(d[k]) is None:
                raise ValueError(f"Campo inválido: {k}")
        if not isinstance(d["question"], str):
            raise ValueError("question debe ser str")
        return PublicParams(d["election_id"], d["question"], n, Point.from_hex(d["public_key"]),
                            d["authority_verify_key"])


@dataclass(frozen=True)
class PublishedBallot:
    election_id: str
    token_id: str
    ciphertext: Ciphertext
    proof: ORProof
    timestamp: str

    def to_dict(self) -> dict:
        return {"version": VERSION, "election_id": self.election_id, "group_id": GROUP_ID,
                "token_id": self.token_id, "ciphertext": _ct_dict(self.ciphertext),
                "proof": self.proof.to_dict(), "timestamp": self.timestamp}

    @staticmethod
    def from_dict(d) -> "PublishedBallot":
        check_published_shape(d)
        return PublishedBallot(d["election_id"], d["token_id"], _ct_from(d["ciphertext"]),
                               ORProof.from_dict(d["proof"]), d["timestamp"])


@dataclass(frozen=True)
class Ballot:
    election_id: str
    token: Token
    ciphertext: Ciphertext
    proof: ORProof
    timestamp: str

    def to_dict(self) -> dict:
        return {"version": VERSION, "election_id": self.election_id, "group_id": GROUP_ID,
                "token": self.token.to_dict(), "ciphertext": _ct_dict(self.ciphertext),
                "proof": self.proof.to_dict(), "timestamp": self.timestamp}

    @staticmethod
    def from_dict(d) -> "Ballot":
        check_ballot_shape(d)
        return Ballot(d["election_id"], Token.from_dict(d["token"]), _ct_from(d["ciphertext"]),
                      ORProof.from_dict(d["proof"]), d["timestamp"])

    def public(self) -> PublishedBallot:
        return PublishedBallot(self.election_id, self.token.token_id, self.ciphertext,
                               self.proof, self.timestamp)


@dataclass(frozen=True)
class Expediente:
    params: PublicParams
    tokens_issued: int
    consumed_token_ids: list[str]
    ballots: list[PublishedBallot]
    aggregate: Ciphertext
    declared_result: int
    closed_at: str
    signature: str

    def body_dict(self) -> dict:
        return {"version": VERSION, "params": self.params.to_dict(),
                "tokens_issued": self.tokens_issued,
                "consumed_token_ids": list(self.consumed_token_ids),
                "ballots": [b.to_dict() for b in self.ballots],
                "aggregate": _ct_dict(self.aggregate),
                "declared_result": self.declared_result, "closed_at": self.closed_at}

    def to_dict(self) -> dict:
        return {**self.body_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return canonical_bytes(self.body_dict())

    @staticmethod
    def from_dict(d) -> "Expediente":
        keys = {"version", "params", "tokens_issued", "consumed_token_ids", "ballots",
                "aggregate", "declared_result", "closed_at", "signature"}
        if not isinstance(d, dict) or set(d) != keys:
            raise MalformedBallot("Expediente con claves inválidas")
        if d["version"] != VERSION:
            raise MalformedBallot("Versión de expediente no soportada")
        for k in ("tokens_issued", "declared_result"):
            if not _is_int(d[k]) or d[k] < 0:
                raise MalformedBallot(f"{k} debe ser un entero >= 0")
        ids = d["consumed_token_ids"]
        if not isinstance(ids, list) or not all(
                isinstance(x, str) and _H32.fullmatch(x) for x in ids):
            raise MalformedBallot("consumed_token_ids inválido")
        if not isinstance(d["ballots"], list):
            raise MalformedBallot("ballots debe ser una lista")
        if not isinstance(d["closed_at"], str) or not d["closed_at"]:
            raise MalformedBallot("closed_at inválido")
        if not isinstance(d["signature"], str) or _H128.fullmatch(d["signature"]) is None:
            raise MalformedBallot("signature inválida")
        agg = d["aggregate"]
        _keys(agg, {"alpha", "beta"}, "aggregate")
        for k in ("alpha", "beta"):
            _hex(agg, k, _H64, "aggregate")
        # El agregado de una elección sin papeletas es la identidad: se admite aquí
        # (y solo aquí); el resto de puntos pasa por Point.from_hex.
        agg_ct = Ciphertext(*(IDENTITY if agg[k] == IDENTITY.to_hex() else Point.from_hex(agg[k])
                              for k in ("alpha", "beta")))
        return Expediente(PublicParams.from_dict(d["params"]), d["tokens_issued"], list(ids),
                          [PublishedBallot.from_dict(b) for b in d["ballots"]], agg_ct,
                          d["declared_result"], d["closed_at"], d["signature"])
