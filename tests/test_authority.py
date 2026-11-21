import json

import pytest
from nacl.signing import VerifyKey

from evoting.crypto.group import IDENTITY, Point
from evoting.protocol.client import build_ballot
from evoting.protocol.models import Expediente, ciphertext_hash


def test_create_params_valid(election):
    Point.decode(bytes.fromhex(election.params.h.to_hex()))
    assert len(election.params.verify_key) == 64
    assert election.store.get_state(election.params.election_id) == "open"


def test_n_max_bounds(election):
    for n in (0, 21):
        with pytest.raises(ValueError):
            election.authority.create_election("q", n)


def test_issue_over_limit(election):
    with pytest.raises(ValueError):
        election.authority.issue_tokens(election.params.election_id, 1)


def test_unknown_and_closed(election):
    with pytest.raises(KeyError):
        election.authority.close("0" * 16)
    with pytest.raises(KeyError):
        election.authority.issue_tokens("0" * 16, 1)
    election.authority.close(election.params.election_id)
    with pytest.raises(ValueError):
        election.authority.issue_tokens(election.params.election_id, 1)


def test_close_tally_and_signature(election):
    eid = election.params.election_id
    for tok, v in zip(election.tokens[:3], (1, 0, 1)):
        b = build_ballot(election.params, tok, v)
        election.store.commit_ballot(eid, b.token.token_id, ciphertext_hash(b.ciphertext),
                                     json.dumps(b.public().to_dict()))
    d = election.authority.close(eid)
    exp = Expediente.from_dict(d)
    assert exp.declared_result == 2
    assert exp.tokens_issued == 20
    assert exp.consumed_token_ids == [t.token_id for t in election.tokens[:3]]
    VerifyKey(bytes.fromhex(election.params.verify_key)).verify(
        exp.signing_bytes(), bytes.fromhex(exp.signature))
    assert election.store.get_state(eid) == "closed"
    published = json.dumps(d)
    stored = json.dumps(election.store.accepted_ballots(eid))
    for t in election.tokens:
        assert t.secret not in published and t.tag not in published
        assert t.secret not in stored and t.tag not in stored


def test_close_twice_is_idempotent(election):
    eid = election.params.election_id
    a = election.authority.close(eid)
    b = election.authority.close(eid)
    assert a == b
    assert election.authority.get_expediente(eid) == a


def test_empty_election_expediente_parses(election):
    d = election.authority.close(election.params.election_id)
    exp = Expediente.from_dict(d)
    assert exp.ballots == [] and exp.declared_result == 0
    assert exp.aggregate.alpha == IDENTITY and exp.aggregate.beta == IDENTITY
    assert exp.to_dict() == d


def test_build_ballot_rejects_2(election):
    with pytest.raises(ValueError):
        build_ballot(election.params, election.tokens[0], 2)
