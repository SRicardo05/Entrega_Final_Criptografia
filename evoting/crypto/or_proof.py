"""Prueba OR (CDS) no interactiva con Fiat-Shamir: el voto cifrado es 0 o 1."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from evoting.crypto.canonical import canonical_bytes
from evoting.crypto.elgamal import Ciphertext
from evoting.crypto.group import GROUP_ID, G, Point, Scalar, base_mul

DOMAIN = "evote/or-proof/v1"

_KEYS = ("A0", "B0", "A1", "B1", "c0", "c1", "s0", "s1")


@dataclass(frozen=True)
class ORProof:
    A0: Point
    B0: Point
    A1: Point
    B1: Point
    c0: Scalar
    c1: Scalar
    s0: Scalar
    s1: Scalar

    def to_dict(self) -> dict[str, str]:
        return {k: getattr(self, k).to_hex() for k in _KEYS}

    @staticmethod
    def from_dict(d) -> "ORProof":
        pts = {k: Point.from_hex(d[k]) for k in _KEYS[:4]}
        scs = {k: Scalar.from_hex(d[k]) for k in _KEYS[4:]}
        return ORProof(**pts, **scs)


def transcript(election_id: str, token_id: str, h: Point, ct: Ciphertext,
               A0: Point, B0: Point, A1: Point, B1: Point) -> bytes:
    return canonical_bytes({
        "domain": DOMAIN,
        "group_id": GROUP_ID,
        "election_id": election_id,
        "token_id": token_id,
        "g": G.to_hex(),
        "h": h.to_hex(),
        "alpha": ct.alpha.to_hex(),
        "beta": ct.beta.to_hex(),
        "A0": A0.to_hex(),
        "B0": B0.to_hex(),
        "A1": A1.to_hex(),
        "B1": B1.to_hex(),
    })


def challenge(t: bytes) -> Scalar:
    return Scalar.from_int(int.from_bytes(hashlib.sha512(t).digest(), "little"))


def _prove_branch(election_id: str, token_id: str, h: Point, ct: Ciphertext,
                  branch: int, r: Scalar) -> ORProof:
    if branch not in (0, 1) or isinstance(branch, bool):
        raise ValueError("branch debe ser 0 o 1")
    u = 1 - branch
    w = Scalar.random()
    c_u, s_u = Scalar.random(), Scalar.random()
    A_v, B_v = base_mul(w), h * w
    beta_u = ct.beta - G * Scalar(u) if u else ct.beta
    A_u = base_mul(s_u) - ct.alpha * c_u
    B_u = h * s_u - beta_u * c_u
    A = [None, None]
    B = [None, None]
    A[branch], B[branch] = A_v, B_v
    A[u], B[u] = A_u, B_u
    c = challenge(transcript(election_id, token_id, h, ct, A[0], B[0], A[1], B[1]))
    c_v = c - c_u
    s_v = w + c_v * r
    cs = [None, None]
    ss = [None, None]
    cs[branch], ss[branch] = c_v, s_v
    cs[u], ss[u] = c_u, s_u
    return ORProof(A[0], B[0], A[1], B[1], cs[0], cs[1], ss[0], ss[1])


def prove(election_id: str, token_id: str, h: Point, ct: Ciphertext,
          v: int, r: Scalar) -> ORProof:
    if isinstance(v, bool) or v not in (0, 1):
        raise ValueError("El voto debe ser 0 o 1")
    return _prove_branch(election_id, token_id, h, ct, v, r)


def verify(election_id: str, token_id: str, h: Point, ct: Ciphertext, proof: ORProof) -> bool:
    try:
        c = challenge(transcript(election_id, token_id, h, ct,
                                 proof.A0, proof.B0, proof.A1, proof.B1))
        if proof.c0 + proof.c1 != c:
            return False
        for j, (A, B, cj, sj) in enumerate((
                (proof.A0, proof.B0, proof.c0, proof.s0),
                (proof.A1, proof.B1, proof.c1, proof.s1))):
            beta_j = ct.beta - G * Scalar(j) if j else ct.beta
            if base_mul(sj) != A + ct.alpha * cj:
                return False
            if h * sj != B + beta_j * cj:
                return False
        return True
    except Exception:
        return False
