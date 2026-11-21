"""Autoridad electoral: creación, emisión de tokens y cierre con expediente firmado."""
from __future__ import annotations

import secrets
import threading

from nacl.signing import SigningKey

from evoting.crypto.elgamal import aggregate, decrypt_aggregate, keygen
from evoting.crypto.tokens import Token, issue_token
from evoting.protocol.models import Expediente, PublicParams, PublishedBallot, utc_now_iso
from evoting.storage.db import Store


class Authority:
    def __init__(self, store: Store):
        self.store = store
        self._lock = threading.RLock()

    def create_election(self, question: str, n_max: int) -> PublicParams:
        if isinstance(n_max, bool) or not isinstance(n_max, int) or not 1 <= n_max <= 20:
            raise ValueError("n_max debe estar entre 1 y 20")
        x, h = keygen()
        seed = secrets.token_bytes(32)
        verify_key = SigningKey(seed).verify_key.encode().hex()
        params = PublicParams(secrets.token_hex(8), question, n_max, h, verify_key)
        self.store.save_election(params, x, secrets.token_bytes(32), seed)
        return params

    def _require(self, eid: str) -> PublicParams:
        params = self.store.load_params(eid)
        if params is None:
            raise KeyError(eid)
        return params

    def issue_tokens(self, eid: str, count: int) -> list[Token]:
        with self._lock:
            params = self._require(eid)
            if self.store.get_state(eid) != "open":
                raise ValueError("La elección está cerrada")
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError("count debe ser un entero >= 0")
            if self.store.count_issued(eid) + count > params.n_max:
                raise ValueError("Se superaría el máximo de votantes de la elección")
            key = self.store.load_token_key(eid)
            tokens = []
            for _ in range(count):
                t = issue_token(key, eid)
                self.store.add_issued_token(eid, t.token_id)
                tokens.append(t)
            return tokens

    def close(self, eid: str) -> dict:
        with self._lock:
            params = self._require(eid)
            if self.store.get_state(eid) == "closed":
                stored = self.store.load_expediente(eid)
                if stored is not None:
                    return stored
            self.store.set_state(eid, "closed")
            x, seed = self.store.load_authority_secrets(eid)
            ballots = [PublishedBallot.from_dict(d) for d in self.store.accepted_ballots(eid)]
            agg = aggregate(b.ciphertext for b in ballots)
            result = decrypt_aggregate(x, agg, len(ballots))
            exp = Expediente(params, self.store.count_issued(eid),
                             [b.token_id for b in ballots], ballots, agg, result,
                             utc_now_iso(), "")
            sig = SigningKey(seed).sign(exp.signing_bytes()).signature.hex()
            d = {**exp.body_dict(), "signature": sig}
            self.store.save_expediente(eid, d)
            return d

    def get_expediente(self, eid: str) -> dict | None:
        return self.store.load_expediente(eid)
