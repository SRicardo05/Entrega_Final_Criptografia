"""CLI: python -m evoting <subcomando>."""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

import httpx


def _write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _http(method: str, url: str, **kw):
    try:
        return httpx.request(method, url, timeout=30, **kw)
    except httpx.HTTPError as e:
        print(f"Error de conexión con el servidor: {e}", file=sys.stderr)
        raise SystemExit(2)


def _checked(r) -> object:
    if r.status_code >= 400:
        print(f"Error {r.status_code}: {r.text}", file=sys.stderr)
        raise SystemExit(1)
    return r.json()


def cmd_serve(a) -> int:
    import uvicorn
    from evoting.api.app import create_app
    uvicorn.run(create_app(a.db), host=a.host, port=a.port)
    return 0


def cmd_admin(a) -> int:
    s = a.server.rstrip("/")
    if a.admin_cmd == "create":
        params = _checked(_http("POST", f"{s}/admin/elections",
                                json={"question": a.question, "n_max": a.n_max}))
        print(json.dumps(params, ensure_ascii=False, indent=2))
        print(f"election_id: {params['election_id']}")
    elif a.admin_cmd == "tokens":
        tokens = _checked(_http("POST", f"{s}/admin/elections/{a.election}/tokens",
                                json={"count": a.count}))
        out = Path(a.out_dir)
        for i, t in enumerate(tokens, 1):
            _write_json(out / f"token_{i:02d}.json", t)
        print(f"{len(tokens)} tokens escritos en {out}")
    elif a.admin_cmd == "close":
        exp = _checked(_http("POST", f"{s}/admin/elections/{a.election}/close"))
        _write_json(Path(a.out), exp)
        print(f"Expediente escrito en {a.out}")
        print(f"Resultado declarado: {exp['declared_result']}")
    return 0


def cmd_vote(a) -> int:
    from evoting.crypto.tokens import Token
    from evoting.protocol.client import build_ballot
    from evoting.protocol.models import PublicParams
    s = a.server.rstrip("/")
    token = Token.from_dict(json.loads(Path(a.token).read_text(encoding="utf-8")))
    params = PublicParams.from_dict(_checked(
        _http("GET", f"{s}/urna/elections/{token.election_id}/params")))
    ballot = build_ballot(params, token, a.choice)
    body = _http("POST", f"{s}/urna/ballots", json=ballot.to_dict()).json()
    print(json.dumps(body, ensure_ascii=False, indent=2))
    return 0 if body.get("accepted") else 1


def cmd_verify(a) -> int:
    from evoting.protocol.verifier import verify_file
    rep = verify_file(a.file)
    print(rep.render())
    try:
        key = json.loads(Path(a.file).read_text(encoding="utf-8"))["params"]["authority_verify_key"]
    except Exception:
        key = "(no disponible)"
    print(f"Clave de verificación de la autoridad: {key}")
    print("Compare esta clave por un canal independiente; de lo contrario se confía en la "
          "clave incluida en el expediente.")
    return 0 if rep.part_a_ok else 1


def cmd_demo(a) -> int:
    from evoting.protocol.authority import Authority
    from evoting.protocol.ballot_box import BallotBox
    from evoting.protocol.client import build_ballot
    from evoting.storage.db import Store
    if not 1 <= a.voters <= 20:
        print("--voters debe estar entre 1 y 20", file=sys.stderr)
        return 2
    rng = random.Random(a.seed)  # RNG no criptográfico solo para elegir los votos de la demo
    store = Store(":memory:")
    try:
        auth = Authority(store)
        box = BallotBox(store)
        params = auth.create_election("¿Aprueba la propuesta?", a.voters)
        tokens = auth.issue_tokens(params.election_id, a.voters)
        choices = [rng.randint(0, 1) for _ in tokens]
        for tok, c in zip(tokens, choices):
            res = box.submit(build_ballot(params, tok, c).to_dict())
            if not res.accepted:
                print(f"Papeleta rechazada: {res.reason}", file=sys.stderr)
                return 1
        exp = auth.close(params.election_id)
    finally:
        store.close()
    _write_json(Path(a.out), exp)
    print(f"Total esperado (votos a favor): {sum(choices)}")
    print(f"Expediente escrito en {a.out}")
    return 0


def cmd_bench(a) -> int:
    from evoting.bench import render_markdown, run_bench, write_results
    if a.repeats < 1:
        print("--repeats debe ser >= 1", file=sys.stderr)
        return 2
    rows = run_bench(repeats=a.repeats)
    write_results(rows, Path(a.out))
    print(render_markdown(rows))
    print(f"Resultados escritos en {a.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="evoting", description="Votación electrónica con ElGamal")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="inicia la API")
    s.add_argument("--db", default="evoting.db")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(func=cmd_serve)

    ad = sub.add_parser("admin", help="operaciones de la autoridad")
    asub = ad.add_subparsers(dest="admin_cmd", required=True)
    c = asub.add_parser("create")
    c.add_argument("--server", required=True)
    c.add_argument("--question", required=True)
    c.add_argument("--n-max", type=int, required=True)
    t = asub.add_parser("tokens")
    t.add_argument("--server", required=True)
    t.add_argument("--election", required=True)
    t.add_argument("--count", type=int, required=True)
    t.add_argument("--out-dir", required=True)
    cl = asub.add_parser("close")
    cl.add_argument("--server", required=True)
    cl.add_argument("--election", required=True)
    cl.add_argument("--out", default="expediente.json")
    ad.set_defaults(func=cmd_admin)

    v = sub.add_parser("vote", help="emite un voto")
    v.add_argument("--server", required=True)
    v.add_argument("--token", required=True)
    v.add_argument("--choice", type=int, choices=[0, 1], required=True)
    v.set_defaults(func=cmd_vote)

    ve = sub.add_parser("verify", help="verifica un expediente")
    ve.add_argument("file")
    ve.set_defaults(func=cmd_verify)

    d = sub.add_parser("demo", help="elección completa en proceso")
    d.add_argument("--voters", type=int, required=True)
    d.add_argument("--out", default="expediente.json")
    d.add_argument("--seed", type=int, default=None)
    d.set_defaults(func=cmd_demo)

    b = sub.add_parser("bench", help="mediciones (N = 1, 5, 10, 20)")
    b.add_argument("--out", default="results")
    b.add_argument("--repeats", type=int, default=5)
    b.set_defaults(func=cmd_bench)
    return p


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
