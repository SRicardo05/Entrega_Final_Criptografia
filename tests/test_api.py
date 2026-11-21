import copy
import json

from fastapi.testclient import TestClient

from evoting.api.app import create_app
from evoting.crypto.tokens import Token
from evoting.protocol.client import build_ballot
from evoting.protocol.models import PublicParams
from evoting.protocol.verifier import verify_expediente


def _setup(tmp_path, n_tokens=3, n_max=5):
    c = TestClient(create_app(str(tmp_path / "t.db")))
    p = c.post("/admin/elections", json={"question": "¿Sí?", "n_max": n_max}).json()
    toks = c.post(f"/admin/elections/{p['election_id']}/tokens", json={"count": n_tokens}).json()
    return c, p, toks


def _ballot(p, tok, choice):
    return build_ballot(PublicParams.from_dict(p), Token.from_dict(tok), choice).to_dict()


def test_api_full_flow(tmp_path):
    c, p, toks = _setup(tmp_path)
    eid = p["election_id"]
    assert c.get(f"/urna/elections/{eid}/params").json() == p
    for tok, ch in zip(toks, [1, 0, 1]):
        r = c.post("/urna/ballots", json=_ballot(p, tok, ch))
        assert r.status_code == 200 and r.json()["accepted"] is True and r.json()["ballot_hash"]
    assert c.get(f"/urna/elections/{eid}/status").json()["accepted_count"] == 3
    exp = c.post(f"/admin/elections/{eid}/close").json()
    assert c.get(f"/admin/elections/{eid}/expediente").json() == exp
    rep = verify_expediente(exp)
    assert rep.part_a_ok and rep.declared_result == 2
    published = json.dumps(exp)
    for tok in toks:
        for k in ("secret", "tag"):
            assert tok[k] not in published


def test_api_rejection_reports_step(tmp_path):
    c, p, toks = _setup(tmp_path)
    b = copy.deepcopy(_ballot(p, toks[0], 1))
    key = next(k for k in b["proof"] if k.startswith("c"))
    v = b["proof"][key]
    b["proof"][key] = ("0" if v[0] != "0" else "1") + v[1:]
    r = c.post("/urna/ballots", json=b)
    assert r.status_code == 400
    assert r.json()["accepted"] is False and r.json()["step_number"] == 3


def test_api_non_object_body(tmp_path):
    c, _, _ = _setup(tmp_path)
    for body in ("[]", "no-json"):
        r = c.post("/urna/ballots", content=body, headers={"content-type": "application/json"})
        assert r.status_code == 400 and r.json()["step"] == "FORMAT"


def test_api_errors(tmp_path):
    c, p, _ = _setup(tmp_path)
    assert c.get("/admin/elections/nope/expediente").status_code == 404
    assert c.get("/urna/elections/nope/params").status_code == 404
    assert c.post("/admin/elections/nope/tokens", json={"count": 1}).status_code == 404
    assert c.post("/admin/elections/nope/close").status_code == 404
    assert c.post("/admin/elections", json={"question": "q", "n_max": 99}).status_code == 400
    r = c.post(f"/admin/elections/{p['election_id']}/tokens", json={"count": 50})
    assert r.status_code == 400 and "detail" in r.json()


def test_api_deep_nesting_is_400_format(tmp_path):
    c, _, _ = _setup(tmp_path)
    hdr = {"content-type": "application/json"}
    r = c.post("/urna/ballots", content="[" * 100000, headers=hdr)
    assert r.status_code == 400 and r.json()["step"] == "FORMAT"
    deep = "[" * 2000 + "]" * 2000
    r = c.post("/urna/ballots", content=deep, headers=hdr)
    assert r.status_code == 400 and r.json()["step"] == "FORMAT"
