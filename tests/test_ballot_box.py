import copy
import re

from evoting.crypto.elgamal import encrypt
from evoting.crypto.group import Scalar, base_mul
from evoting.crypto.or_proof import _prove_branch, prove
from evoting.protocol.authority import Authority
from evoting.protocol.ballot_box import BallotBox, RejectStep
from evoting.protocol.client import build_ballot


def ballot_dict(e, i, choice=1):
    return build_ballot(e.params, e.tokens[i], choice).to_dict()


def assert_rejected(result, step):
    assert not result.accepted
    assert result.step == step
    assert result.reason and result.ballot_hash is None


def test_valid_ballots_accepted(election):
    e = election
    r0 = e.box.submit(ballot_dict(e, 0, 0))
    r1 = e.box.submit(ballot_dict(e, 1, 1))
    for r in (r0, r1):
        assert r.accepted and r.step is None
        assert re.fullmatch(r"[0-9a-f]{64}", r.ballot_hash)
    assert r0.ballot_hash != r1.ballot_hash
    assert e.box.status(e.params.election_id) == {
        "election_id": e.params.election_id, "state": "open", "accepted_count": 2}


def test_status_unknown_election(election):
    assert election.box.status("0" * 16) == {
        "election_id": "0" * 16, "state": None, "accepted_count": 0}


def test_vote_value_2(election):
    e = election
    d = ballot_dict(e, 0)
    ct, r = encrypt(e.params.h, 2)
    proof = _prove_branch(e.params.election_id, e.tokens[0].token_id, e.params.h, ct, 1, r)
    d["ciphertext"] = {"alpha": ct.alpha.to_hex(), "beta": ct.beta.to_hex()}
    d["proof"] = proof.to_dict()
    assert_rejected(e.box.submit(d), RejectStep.PROOF)


def test_modified_commitment_valid_point(election):
    d = ballot_dict(election, 0)
    d["proof"]["A0"] = base_mul(Scalar.random()).to_hex()
    assert_rejected(election.box.submit(d), RejectStep.PROOF)


def test_commitment_out_of_group(election):
    for bad in ("ec" + "ff" * 30 + "7f", "ed" + "ff" * 30 + "7f"):
        d = ballot_dict(election, 0)
        d["proof"]["A0"] = bad
        assert_rejected(election.box.submit(d), RejectStep.ELEMENTS)


def test_altered_challenge(election):
    d = ballot_dict(election, 0)
    d["proof"]["c0"] = (Scalar.from_hex(d["proof"]["c0"]) + Scalar(1)).to_hex()
    assert_rejected(election.box.submit(d), RejectStep.PROOF)


def test_altered_challenge_sum_preserved(election):
    d = ballot_dict(election, 0)
    delta = Scalar(12345)
    d["proof"]["c0"] = (Scalar.from_hex(d["proof"]["c0"]) + delta).to_hex()
    d["proof"]["c1"] = (Scalar.from_hex(d["proof"]["c1"]) - delta).to_hex()
    r = election.box.submit(d)
    assert_rejected(r, RejectStep.PROOF)
    assert "error interno" not in r.reason


def test_altered_response(election):
    d = ballot_dict(election, 0)
    d["proof"]["s1"] = (Scalar.from_hex(d["proof"]["s1"]) + Scalar(1)).to_hex()
    assert_rejected(election.box.submit(d), RejectStep.PROOF)


def test_alpha_small_order(election):
    d = ballot_dict(election, 0)
    # y = p-1, x = 0: punto de orden 2 de la curva
    d["ciphertext"]["alpha"] = "ec" + "ff" * 30 + "7f"
    assert_rejected(election.box.submit(d), RejectStep.ELEMENTS)


def test_missing_component(election):
    d = ballot_dict(election, 0)
    del d["ciphertext"]["beta"]
    r = election.box.submit(d)
    assert_rejected(r, RejectStep.FORMAT)
    assert "error interno" not in r.reason


def test_wrong_types_rejected_at_format(election):
    for bad in (123, None, []):
        d = ballot_dict(election, 0)
        d["ciphertext"]["alpha"] = bad
        r = election.box.submit(d)
        assert_rejected(r, RejectStep.FORMAT)
        assert "error interno" not in r.reason
    r = election.box.submit("hola")
    assert_rejected(r, RejectStep.FORMAT)
    assert "error interno" not in r.reason


def test_uppercase_hex_rejected_at_format(election):
    d = ballot_dict(election, 0)
    d["ciphertext"]["alpha"] = d["ciphertext"]["alpha"].upper()
    r = election.box.submit(d)
    assert_rejected(r, RejectStep.FORMAT)
    assert "error interno" not in r.reason


def test_unknown_or_closed_election(election):
    e = election
    d = ballot_dict(e, 0)
    d["election_id"] = "0" * 16
    assert_rejected(e.box.submit(d), RejectStep.FORMAT)
    e.authority.close(e.params.election_id)
    assert_rejected(e.box.submit(ballot_dict(e, 1)), RejectStep.FORMAT)


def test_forged_token(election):
    d = ballot_dict(election, 0)
    d["token"]["tag"] = "ab" * 32
    assert_rejected(election.box.submit(d), RejectStep.TOKEN)


def test_token_other_election(election):
    e = election
    other = e.authority.create_election("otra", 5)
    tok = e.authority.issue_tokens(other.election_id, 1)[0]
    d = build_ballot(e.params, tok, 1).to_dict()  # token de otra elección en esta
    assert_rejected(e.box.submit(d), RejectStep.TOKEN)


def test_repeated_token(election):
    e = election
    assert e.box.submit(ballot_dict(e, 0, 1)).accepted
    assert_rejected(e.box.submit(ballot_dict(e, 0, 0)), RejectStep.TOKEN)


def test_exact_replay(election):
    d = ballot_dict(election, 0)
    assert election.box.submit(d).accepted
    assert_rejected(election.box.submit(copy.deepcopy(d)), RejectStep.TOKEN)


def test_copied_ballot_new_token(election):
    e = election
    d = ballot_dict(e, 0)
    assert e.box.submit(d).accepted
    d2 = copy.deepcopy(d)
    d2["token"] = e.tokens[1].to_dict()
    assert_rejected(e.box.submit(d2), RejectStep.PROOF)


def test_copied_ciphertext_regenerated_proof(election):
    e = election
    ct, r = encrypt(e.params.h, 1)
    ds = []
    for i in (0, 1):
        d = ballot_dict(e, i)
        d["ciphertext"] = {"alpha": ct.alpha.to_hex(), "beta": ct.beta.to_hex()}
        d["proof"] = prove(e.params.election_id, e.tokens[i].token_id, e.params.h, ct, 1, r).to_dict()
        ds.append(d)
    assert e.box.submit(ds[0]).accepted
    assert_rejected(e.box.submit(ds[1]), RejectStep.REPLAY)


def test_commit_race(election, monkeypatch):
    e = election
    d = ballot_dict(e, 0)
    assert e.box.submit(d).accepted
    monkeypatch.setattr(e.store, "is_consumed", lambda token_id: False)
    monkeypatch.setattr(e.store, "has_ct_hash", lambda h: False)
    assert_rejected(e.box.submit(copy.deepcopy(d)), RejectStep.COMMIT)
    assert e.box.status(e.params.election_id)["accepted_count"] == 1


def test_close_race_maps_to_format(election, monkeypatch):
    e = election
    d = ballot_dict(e, 0)
    monkeypatch.setattr(e.store, "has_ct_hash",
                        lambda h: (e.store.set_state(e.params.election_id, "closed"), False)[1])
    assert_rejected(e.box.submit(d), RejectStep.FORMAT)
