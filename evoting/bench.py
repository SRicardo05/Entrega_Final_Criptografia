"""Mediciones: tamaño del ballot y tiempos de creación, verificación por voto y auditoría."""
from __future__ import annotations

import csv
import statistics
import time
from pathlib import Path

from evoting.crypto.canonical import canonical_bytes
from evoting.protocol.authority import Authority
from evoting.protocol.ballot_box import BallotBox
from evoting.protocol.client import build_ballot
from evoting.protocol.verifier import verify_expediente
from evoting.storage.db import Store

_COLUMNS = ("n", "ballot_bytes", "create_ms", "verify_ms_per_vote", "audit_ms")


def _once(n: int) -> dict:
    """Una elección completa con n votantes; devuelve tamaño y tiempos (ms)."""
    store = Store(":memory:")
    try:
        auth = Authority(store)
        box = BallotBox(store)
        params = auth.create_election("Pregunta de prueba", n)
        tokens = auth.issue_tokens(params.election_id, n)
        t0 = time.perf_counter()
        ballots = [build_ballot(params, tok, i % 2).to_dict() for i, tok in enumerate(tokens)]
        t_create = time.perf_counter() - t0
        t0 = time.perf_counter()
        for b in ballots:
            if not box.submit(b).accepted:
                raise RuntimeError("la urna rechazó una papeleta válida durante el benchmark")
        t_submit = time.perf_counter() - t0
        exp = auth.close(params.election_id)
        t0 = time.perf_counter()
        rep = verify_expediente(exp)
        t_audit = time.perf_counter() - t0
        if not rep.part_a_ok:
            raise RuntimeError("el expediente del benchmark no verifica")
    finally:
        store.close()
    return {"ballot_bytes": max(len(canonical_bytes(b)) for b in ballots),
            "create_ms": t_create * 1000 / n,
            "verify_ms_per_vote": t_submit * 1000 / n,
            "audit_ms": t_audit * 1000}


def run_bench(sizes=(1, 5, 10, 20), repeats: int = 5) -> list[dict]:
    """Mediana de `repeats` repeticiones por tamaño.

    create_ms es el tiempo de build_ballot por papeleta; verify_ms_per_vote es el tiempo
    de BallotBox.submit por papeleta (pipeline completo); audit_ms es verify_expediente.
    """
    if repeats < 1:
        raise ValueError("repeats debe ser >= 1")
    rows = []
    for n in sizes:
        runs = [_once(n) for _ in range(repeats)]
        row = {"n": n}
        for k in _COLUMNS[1:]:
            v = statistics.median(r[k] for r in runs)
            row[k] = int(v) if k == "ballot_bytes" else v
        rows.append(row)
    return rows


def render_markdown(rows: list[dict]) -> str:
    lines = ["| N.º de votos | Tamaño de ballot (bytes) | Tiempo de creación (ms) | "
             "Tiempo de verificación por voto (ms) | Tiempo total de auditoría (ms) |",
             "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['n']} | {r['ballot_bytes']} | {r['create_ms']:.3f} | "
                     f"{r['verify_ms_per_vote']:.3f} | {r['audit_ms']:.3f} |")
    return "\n".join(lines) + "\n"


def write_results(rows: list[dict], out_dir: Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metrics.md").write_text(render_markdown(rows), encoding="utf-8")
    with (out_dir / "metrics.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(_COLUMNS)
        for r in rows:
            w.writerow([r["n"], r["ballot_bytes"], f"{r['create_ms']:.6f}",
                        f"{r['verify_ms_per_vote']:.6f}", f"{r['audit_ms']:.6f}"])
