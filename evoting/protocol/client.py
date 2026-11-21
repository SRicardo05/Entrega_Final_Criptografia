"""Cliente de votación: construye la papeleta cifrada con su prueba OR."""
from __future__ import annotations

from evoting.crypto.elgamal import encrypt
from evoting.crypto.or_proof import prove
from evoting.crypto.tokens import Token
from evoting.protocol.models import Ballot, PublicParams, utc_now_iso


def build_ballot(params: PublicParams, token: Token, choice: int) -> Ballot:
    if isinstance(choice, bool) or choice not in (0, 1):
        raise ValueError("La opción debe ser 0 o 1")
    ct, r = encrypt(params.h, choice)
    proof = prove(params.election_id, token.token_id, params.h, ct, choice, r)
    return Ballot(params.election_id, token, ct, proof, utc_now_iso())
