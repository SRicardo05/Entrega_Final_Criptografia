import json
from dataclasses import replace

import pytest

from evoting.crypto.canonical import canonical_bytes, sha256_hex
from evoting.crypto.elgamal import encrypt, keygen
from evoting.crypto.group import InvalidElement, Scalar, base_mul
from evoting.crypto.or_proof import ORProof, _prove_branch, prove, transcript, verify

E, T = "elec-1", "tok-1"


def setup(v):
    _, h = keygen()
    ct, r = encrypt(h, v)
    return h, ct, r


@pytest.mark.parametrize("v", [0, 1])
def test_proof_vote_0_and_1_verify(v):
    h, ct, r = setup(v)
    assert verify(E, T, h, ct, prove(E, T, h, ct, v, r))


def test_prove_rejects_value_2():
    h, ct, r = setup(1)
    with pytest.raises(ValueError):
        prove(E, T, h, ct, 2, r)


def test_vote_2_forged_proof_fails():
    h, ct, r = setup(2)
    for b in (0, 1):
        assert not verify(E, T, h, ct, _prove_branch(E, T, h, ct, b, r))


def test_branch_invalid():
    h, ct, r = setup(1)
    with pytest.raises(ValueError):
        _prove_branch(E, T, h, ct, 2, r)


def test_modified_commitment_fails():
    h, ct, r = setup(1)
    p = prove(E, T, h, ct, 1, r)
    assert not verify(E, T, h, ct, replace(p, A0=base_mul(Scalar.random())))


def test_altered_challenge_fails():
    h, ct, r = setup(0)
    p = prove(E, T, h, ct, 0, r)
    assert not verify(E, T, h, ct, replace(p, c0=p.c0 + Scalar(1)))


@pytest.mark.parametrize("v", [0, 1])
def test_challenge_shift_sum_preserved_fails(v):
    # c0 + d, c1 - d: la suma c0 + c1 = c se conserva; deben fallar las ecuaciones de rama
    h, ct, r = setup(v)
    p = prove(E, T, h, ct, v, r)
    d = Scalar(12345)
    assert (p.c0 + d) + (p.c1 - d) == p.c0 + p.c1
    assert not verify(E, T, h, ct, replace(p, c0=p.c0 + d, c1=p.c1 - d))


def test_altered_response_fails():
    h, ct, r = setup(0)
    p = prove(E, T, h, ct, 0, r)
    assert not verify(E, T, h, ct, replace(p, s1=p.s1 + Scalar(1)))


def test_other_token_id_fails():
    h, ct, r = setup(1)
    p = prove(E, T, h, ct, 1, r)
    assert not verify(E, "tok-2", h, ct, p)


def test_other_election_fails():
    h, ct, r = setup(1)
    p = prove(E, T, h, ct, 1, r)
    assert not verify("elec-2", T, h, ct, p)


def test_transcript_key_order():
    h, ct, r = setup(1)
    p = prove(E, T, h, ct, 1, r)
    t = transcript(E, T, h, ct, p.A0, p.B0, p.A1, p.B1)
    assert t.startswith(b'{"A0":"')
    assert list(json.loads(t)) == ["A0", "A1", "B0", "B1", "alpha", "beta", "domain",
                                   "election_id", "g", "group_id", "h", "token_id"]


def test_proof_dict_roundtrip():
    h, ct, r = setup(1)
    p = prove(E, T, h, ct, 1, r)
    d = p.to_dict()
    assert list(d) == ["A0", "B0", "A1", "B1", "c0", "c1", "s0", "s1"]
    assert ORProof.from_dict(d) == p
    d["A0"] = "zz"
    with pytest.raises(InvalidElement):
        ORProof.from_dict(d)


def test_canonical_helpers():
    assert canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert len(sha256_hex(b"x")) == 64
