"""Urna electoral con pipeline de rechazo explícito y ordenado (pasos 0 a 5)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import IntEnum

from evoting.crypto.canonical import canonical_bytes, sha256_hex
from evoting.crypto.group import InvalidElement
from evoting.crypto.or_proof import verify
from evoting.crypto.tokens import Token, verify_token
from evoting.protocol.models import (Ballot, MalformedBallot, ciphertext_hash,
                                     check_ballot_shape)
from evoting.storage.db import DuplicateError, ElectionClosedError, Store


class RejectStep(IntEnum):
    FORMAT = 0
    TOKEN = 1
    ELEMENTS = 2
    PROOF = 3
    REPLAY = 4
    COMMIT = 5


@dataclass
class SubmitResult:
    accepted: bool
    step: RejectStep | None
    reason: str
    ballot_hash: str | None = None


def _reject(step: RejectStep, reason: str) -> SubmitResult:
    return SubmitResult(False, step, reason, None)


class BallotBox:
    def __init__(self, store: Store):
        self.store = store

    def submit(self, raw: object) -> SubmitResult:
        try:
            return self._submit(raw)
        except Exception:  # la urna nunca lanza; ante lo inesperado rechaza (falla cerrada)
            return _reject(RejectStep.FORMAT, "error interno al procesar la papeleta")

    def _submit(self, raw: object) -> SubmitResult:
        store = self.store
        # 0 FORMAT
        try:
            check_ballot_shape(raw)
        except MalformedBallot as e:
            return _reject(RejectStep.FORMAT, f"formato inválido: {e}")
        eid = raw["election_id"]
        state = store.get_state(eid)
        if state is None:
            return _reject(RejectStep.FORMAT, "la elección no existe")
        if state != "open":
            return _reject(RejectStep.FORMAT, "la elección está cerrada")
        # 1 TOKEN
        try:
            token = Token.from_dict(raw["token"])
        except ValueError:
            return _reject(RejectStep.FORMAT, "formato de token inválido")
        if token.election_id != eid:
            return _reject(RejectStep.TOKEN, "el token pertenece a otra elección")
        if not verify_token(store.load_token_key(eid), token):
            return _reject(RejectStep.TOKEN, "token no autorizado")
        if store.is_consumed(token.token_id):
            return _reject(RejectStep.TOKEN, "token ya utilizado")
        # 2 ELEMENTS
        try:
            ballot = Ballot.from_dict(raw)
        except (InvalidElement, MalformedBallot, ValueError):
            return _reject(RejectStep.ELEMENTS, "elementos del grupo inválidos")
        # 3 PROOF
        params = store.load_params(eid)
        if params is None or not verify(eid, token.token_id, params.h, ballot.ciphertext,
                                        ballot.proof):
            return _reject(RejectStep.PROOF, "prueba OR inválida")
        # 4 REPLAY
        ct_hash = ciphertext_hash(ballot.ciphertext)
        if store.has_ct_hash(ct_hash):
            return _reject(RejectStep.REPLAY, "cifrado ya registrado")
        # 5 COMMIT
        public = ballot.public().to_dict()
        try:
            store.commit_ballot(eid, token.token_id, ct_hash, json.dumps(public))
        except ElectionClosedError:
            return _reject(RejectStep.FORMAT, "la elección está cerrada")
        except DuplicateError:
            return _reject(RejectStep.COMMIT, "token o cifrado duplicado al registrar")
        return SubmitResult(True, None, "papeleta aceptada",
                            sha256_hex(canonical_bytes(public)))

    def status(self, eid: str) -> dict:
        state = self.store.get_state(eid)
        count = 0 if state is None else len(self.store.accepted_ballots(eid))
        return {"election_id": eid, "state": state, "accepted_count": count}
