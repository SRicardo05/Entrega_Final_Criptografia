"""Verificador offline: lee solo el expediente publicado.

Parte A: comprobaciones criptográficas. Parte B: resultado declarado por la
autoridad, que NO es verificable (no existe prueba de descifrado correcto).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from nacl.signing import VerifyKey

from evoting.crypto.canonical import canonical_bytes
from evoting.crypto.elgamal import aggregate
from evoting.crypto.or_proof import verify as verify_or
from evoting.protocol.models import (VERSION, PublicParams, PublishedBallot, check_published_shape,
                                     ciphertext_hash)


@dataclass
class VerificationReport:
    signature_ok: bool = False
    params_ok: bool = False
    ballots_ok: bool = False
    ballot_errors: list[str] = field(default_factory=list)
    no_duplicates: bool = False
    count_ok: bool = False
    consumed_match: bool = False
    aggregate_matches: bool = False
    aggregate_recomputed: dict = field(default_factory=dict)
    declared_result: int = 0
    declared_in_range: bool = False

    @property
    def part_a_ok(self) -> bool:
        return all((self.signature_ok, self.params_ok, self.ballots_ok, self.no_duplicates,
                    self.count_ok, self.consumed_match, self.aggregate_matches))

    def render(self) -> str:
        def ok(b: bool) -> str:
            return "OK" if b else "FALLA"
        lines = ["A. VERIFICADO CRIPTOGRÁFICAMENTE",
                 f"  [{ok(self.signature_ok)}] Firma Ed25519 de la autoridad sobre el expediente",
                 f"  [{ok(self.params_ok)}] Parámetros públicos válidos",
                 f"  [{ok(self.ballots_ok)}] Papeletas: forma, elección y prueba OR",
                 f"  [{ok(self.no_duplicates)}] Sin token_id ni cifrado repetidos",
                 f"  [{ok(self.count_ok)}] Cantidad de papeletas dentro de n_max y de tokens emitidos",
                 f"  [{ok(self.consumed_match)}] Tokens consumidos coinciden con las papeletas",
                 f"  [{ok(self.aggregate_matches)}] Agregado recalculado coincide con el declarado"]
        lines += [f"    - {e}" for e in self.ballot_errors]
        lines.append(f"  Resultado de la parte A: {ok(self.part_a_ok)}")
        lines += ["",
                  "B. DECLARADO POR LA AUTORIDAD (NO VERIFICABLE: no hay prueba de descifrado correcto)",
                  f"  Resultado declarado (votos a favor): {self.declared_result}",
                  f"  Verificación de rango: {'dentro de rango' if self.declared_in_range else 'fuera de rango'}"]
        return "\n".join(lines)


def _fail(msg: str) -> VerificationReport:
    return VerificationReport(ballot_errors=[msg])


def verify_expediente(d: dict) -> VerificationReport:
    try:
        return _verify(d)
    except Exception as e:  # nunca propagar ante entrada hostil
        return _fail(f"expediente ilegible: {type(e).__name__}")


def _verify(d) -> VerificationReport:
    if not isinstance(d, dict):
        return _fail("el expediente no es un objeto JSON")
    rep = VerificationReport()
    try:
        if d.get("version") != VERSION:
            raise ValueError("versión de expediente no soportada")
        params = PublicParams.from_dict(d.get("params"))
        rep.params_ok = True
    except Exception as e:
        rep.ballot_errors.append(f"parámetros inválidos: {e}")
        params = None
    # Firma
    try:
        body = {k: v for k, v in d.items() if k != "signature"}
        vk = VerifyKey(bytes.fromhex(d["params"]["authority_verify_key"]))
        vk.verify(canonical_bytes(body), bytes.fromhex(d["signature"]))
        rep.signature_ok = True
    except Exception:
        rep.signature_ok = False
    ballots = d.get("ballots")
    consumed = d.get("consumed_token_ids")
    issued = d.get("tokens_issued")
    declared = d.get("declared_result")
    if not isinstance(ballots, list):
        rep.ballot_errors.append("ballots debe ser una lista")
        ballots = []
        shape_ok = False
    else:
        shape_ok = True
    if not isinstance(consumed, list) or not all(isinstance(x, str) for x in consumed):
        rep.ballot_errors.append("consumed_token_ids inválido")
        consumed = []
        shape_ok = False
    if not isinstance(issued, int) or isinstance(issued, bool):
        rep.ballot_errors.append("tokens_issued inválido")
        issued = None
        shape_ok = False
    closed_at = d.get("closed_at")
    if not isinstance(closed_at, str) or not closed_at:
        rep.ballot_errors.append("closed_at inválido")
        shape_ok = False
    if isinstance(declared, int) and not isinstance(declared, bool):
        rep.declared_result = declared
    else:
        rep.ballot_errors.append("declared_result inválido")
        declared = None
    # Papeletas, cada una de forma independiente
    good: list[PublishedBallot] = []
    all_ok = shape_ok and params is not None
    for i, raw in enumerate(ballots):
        try:
            check_published_shape(raw)
            b = PublishedBallot.from_dict(raw)
        except Exception as e:
            rep.ballot_errors.append(f"papeleta {i}: forma o elementos inválidos ({e})")
            all_ok = False
            continue
        good.append(b)
        if params is None:
            continue
        if b.election_id != params.election_id:
            rep.ballot_errors.append(f"papeleta {i}: pertenece a otra elección")
            all_ok = False
        elif not verify_or(b.election_id, b.token_id, params.h, b.ciphertext, b.proof):
            rep.ballot_errors.append(f"papeleta {i}: prueba OR inválida")
            all_ok = False
    rep.ballots_ok = all_ok
    n = len(ballots)
    ids = [b.token_id for b in good]
    hashes = [ciphertext_hash(b.ciphertext) for b in good]
    rep.no_duplicates = (len(set(ids)) == len(ids) and len(set(hashes)) == len(hashes)
                         and len(set(consumed)) == len(consumed))
    rep.count_ok = (params is not None and issued is not None
                    and n <= params.n_max and n <= issued)
    rep.consumed_match = (len(good) == n and set(consumed) == set(ids)
                          and len(consumed) == len(ids))
    agg = aggregate(b.ciphertext for b in good)
    rep.aggregate_recomputed = {"alpha": agg.alpha.to_hex(), "beta": agg.beta.to_hex()}
    da = d.get("aggregate")
    rep.aggregate_matches = (isinstance(da, dict) and da.get("alpha") == rep.aggregate_recomputed["alpha"]
                             and da.get("beta") == rep.aggregate_recomputed["beta"])
    rep.declared_in_range = declared is not None and 0 <= declared <= n
    return rep


def verify_file(path) -> VerificationReport:
    try:
        d = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        return _fail(f"no se pudo leer el expediente: {type(e).__name__}")
    return verify_expediente(d)
