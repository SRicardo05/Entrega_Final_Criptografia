import pytest

from evoting.crypto.elgamal import keygen
from evoting.protocol.models import PublicParams
from evoting.storage.db import DuplicateError, ElectionClosedError, Store

EID = "ab12cd34ef567890"


def make_params(eid=EID):
    x, h = keygen()
    return x, PublicParams(eid, "¿Aprueba?", 5, h, "0" * 64)


@pytest.fixture
def store():
    s = Store(":memory:")
    x, p = make_params()
    s.save_election(p, x, b"k" * 32, b"s" * 32)
    yield s
    s.close()


def test_commit_and_list(store):
    store.commit_ballot(EID, "t1", "h1", '{"a": 1}')
    store.commit_ballot(EID, "t2", "h2", '{"a": 2}')
    assert store.accepted_ballots(EID) == [{"a": 1}, {"a": 2}]
    assert store.is_consumed("t1") and not store.is_consumed("t3")
    assert store.has_ct_hash("h1") and not store.has_ct_hash("h9")


def test_duplicate_token_raises(store):
    store.commit_ballot(EID, "t1", "h1", "{}")
    with pytest.raises(DuplicateError):
        store.commit_ballot(EID, "t1", "h2", "{}")


def test_duplicate_ct_hash_raises(store):
    store.commit_ballot(EID, "t1", "h1", "{}")
    with pytest.raises(DuplicateError):
        store.commit_ballot(EID, "t2", "h1", "{}")


def test_failed_commit_is_atomic(store):
    store.commit_ballot(EID, "t1", "h1", "{}")
    with pytest.raises(DuplicateError):
        store.commit_ballot(EID, "t2", "h1", "{}")
    assert len(store.accepted_ballots(EID)) == 1
    assert not store.is_consumed("t2")
    store.add_issued_token(EID, "t3")
    store.commit_ballot(EID, "t3", "h3", "{}")
    with pytest.raises(DuplicateError):
        store.commit_ballot(EID, "t3", "h4", "{}")
    assert not store.has_ct_hash("h4")


def test_issued_token_consumed_flow(store):
    store.add_issued_token(EID, "t1")
    assert store.count_issued(EID) == 1 and not store.is_consumed("t1")
    store.commit_ballot(EID, "t1", "h1", "{}")
    assert store.is_consumed("t1")


def test_persists_across_reopen(tmp_path):
    path = tmp_path / "e.db"
    s = Store(path)
    x, p = make_params()
    s.save_election(p, x, b"k" * 32, b"s" * 32)
    s.commit_ballot(EID, "t1", "h1", '{"a": 1}')
    s.save_expediente(EID, {"z": 1})
    s.close()
    s2 = Store(path)
    assert s2.load_params(EID) == p
    assert s2.load_authority_secrets(EID) == (x, b"s" * 32)
    assert s2.load_token_key(EID) == b"k" * 32
    assert s2.accepted_ballots(EID) == [{"a": 1}]
    assert s2.is_consumed("t1")
    assert s2.load_expediente(EID) == {"z": 1}
    s2.close()


def test_commit_rejected_when_closed(store):
    store.set_state(EID, "closed")
    with pytest.raises(ElectionClosedError):
        store.commit_ballot(EID, "t1", "h1", "{}")
    assert store.accepted_ballots(EID) == []
    assert not store.is_consumed("t1")


def test_state_transitions(store):
    assert store.get_state(EID) == "open"
    store.set_state(EID, "closed")
    assert store.get_state(EID) == "closed"
    assert store.get_state("0" * 16) is None
    assert store.load_params("0" * 16) is None
    assert store.load_expediente(EID) is None
    with pytest.raises(KeyError):
        store.load_token_key("0" * 16)
    with pytest.raises(KeyError):
        store.load_authority_secrets("0" * 16)
