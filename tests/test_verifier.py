import copy
import json

from nacl.signing import SigningKey

from evoting.crypto.canonical import canonical_bytes
from evoting.crypto.group import G
from evoting.protocol.client import build_ballot
from evoting.protocol.verifier import verify_expediente, verify_file


def resign(d, store, eid):
    seed = store.load_authority_secrets(eid)[1]
    body = {k: v for k, v in d.items() if k != "signature"}
    sig = SigningKey(seed).sign(canonical_bytes(body)).signature.hex()
    return {**body, "signature": sig}


def _vote(el, choices):
    for tok, c in zip(el.tokens, choices):
        r = el.box.submit(build_ballot(el.params, tok, c).to_dict())
        assert r.accepted


def _closed(el, choices):
    _vote(el, choices)
    return el.authority.close(el.params.election_id)


MIXED = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1]


def test_honest_election_verifies(election):
    d = _closed(election, MIXED)
    rep = verify_expediente(d)
    assert rep.part_a_ok
    assert rep.declared_result == sum(MIXED)
    assert rep.declared_in_range
    assert "A. VERIFICADO CRIPTOGRÁFICAMENTE" in rep.render()


def test_empty_election_verifies(election):
    d = election.authority.close(election.params.election_id)
    rep = verify_expediente(d)
    assert rep.part_a_ok and rep.declared_result == 0


def test_tampered_ballot_detected(election):
    d = copy.deepcopy(_closed(election, MIXED))
    old = d["ballots"][0]["ciphertext"]["alpha"]
    d["ballots"][0]["ciphertext"]["alpha"] = (G + G).to_hex() if old != (G + G).to_hex() else G.to_hex()
    rep = verify_expediente(d)
    assert not rep.signature_ok
    assert not rep.ballots_ok
    assert not rep.part_a_ok
    rep2 = verify_expediente(resign(d, election.store, election.params.election_id))
    assert rep2.signature_ok and not rep2.ballots_ok


def test_tampered_aggregate_detected(election):
    d = copy.deepcopy(_closed(election, MIXED))
    d["aggregate"]["alpha"] = (G + G).to_hex()
    rep = verify_expediente(resign(d, election.store, election.params.election_id))
    assert rep.signature_ok and not rep.aggregate_matches and not rep.part_a_ok


def test_tampered_signature_detected(election):
    d = copy.deepcopy(_closed(election, MIXED))
    s = d["signature"]
    d["signature"] = ("0" if s[0] != "0" else "1") + s[1:]
    rep = verify_expediente(d)
    assert not rep.signature_ok and not rep.part_a_ok


def test_dishonest_result_in_range_not_detectable(election):
    d = copy.deepcopy(_closed(election, MIXED))
    d["declared_result"] = 0 if sum(MIXED) else 1
    rep = verify_expediente(resign(d, election.store, election.params.election_id))
    assert rep.part_a_ok and rep.declared_in_range
    assert "NO VERIFICABLE" in rep.render()
    assert "dentro de rango" in rep.render()


def test_result_out_of_range(election):
    d = copy.deepcopy(_closed(election, MIXED))
    d["declared_result"] = len(MIXED) + 1
    rep = verify_expediente(resign(d, election.store, election.params.election_id))
    assert not rep.declared_in_range
    assert "fuera de rango" in rep.render()


def test_injected_ballot_detected(election):
    d = copy.deepcopy(_closed(election, MIXED))
    extra = build_ballot(election.params, election.tokens[15], 1).public().to_dict()
    d["ballots"].append(extra)
    rep = verify_expediente(resign(d, election.store, election.params.election_id))
    assert not rep.consumed_match and not rep.part_a_ok


def test_duplicates_and_foreign_election(election):
    closed = _closed(election, MIXED)
    d = copy.deepcopy(closed)
    d["consumed_token_ids"].append(d["consumed_token_ids"][0])
    rep = verify_expediente(resign(d, election.store, election.params.election_id))
    assert not rep.no_duplicates and not rep.part_a_ok
    d = copy.deepcopy(closed)
    d["ballots"][0]["election_id"] = "0" * 16
    rep = verify_expediente(resign(d, election.store, election.params.election_id))
    assert not rep.ballots_ok


def test_wrong_version_detected(election):
    d = copy.deepcopy(_closed(election, MIXED))
    d["version"] = "v2"
    rep = verify_expediente(resign(d, election.store, election.params.election_id))
    assert rep.signature_ok and not rep.params_ok and not rep.part_a_ok


def test_bad_closed_at_detected(election):
    closed = _closed(election, MIXED)
    for bad in ("", 5, None):
        d = copy.deepcopy(closed)
        d["closed_at"] = bad
        rep = verify_expediente(resign(d, election.store, election.params.election_id))
        assert rep.signature_ok and not rep.part_a_ok


def test_malformed_never_raises():
    for bad in (None, 5, [], {}, {"params": 3, "ballots": "x"}, "texto"):
        rep = verify_expediente(bad)
        assert not rep.part_a_ok
        assert rep.ballot_errors
        rep.render()


def test_garbage_ballot_does_not_stop_others(election):
    d = copy.deepcopy(_closed(election, MIXED))
    d["ballots"][0] = {"x": 1}
    rep = verify_expediente(resign(d, election.store, election.params.election_id))
    assert not rep.ballots_ok and len(rep.ballot_errors) == 1


def test_verify_file(election, tmp_path):
    d = _closed(election, MIXED)
    p = tmp_path / "exp.json"
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    assert verify_file(p).part_a_ok
    p.write_text("{no json", encoding="utf-8")
    assert not verify_file(p).part_a_ok
