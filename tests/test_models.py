import copy

import pytest

from evoting.crypto import elgamal
from evoting.crypto.canonical import canonical_bytes, sha256_hex
from evoting.crypto.group import G, GROUP_ID, InvalidElement, Scalar, base_mul
from evoting.crypto.or_proof import prove
from evoting.crypto.tokens import issue_token
from evoting.protocol.models import (
    VERSION, Ballot, Expediente, MalformedBallot, PublicParams, PublishedBallot,
    check_ballot_shape, check_published_shape, ciphertext_hash, utc_now_iso,
)

EID = "0123456789abcdef"
KEY = b"k" * 32


def _params():
    _, h = elgamal.keygen()
    return PublicParams(EID, "¿Aprueba?", 5, h, "ab" * 32)


def _ballot():
    p = _params()
    t = issue_token(KEY, EID)
    ct, r = elgamal.encrypt(p.h, 1)
    proof = prove(EID, t.token_id, p.h, ct, 1, r)
    return Ballot(EID, t, ct, proof, utc_now_iso()), p


def test_params_roundtrip():
    p = _params()
    d = p.to_dict()
    assert d["generator"] == G.to_hex() and d["group_id"] == GROUP_ID
    assert d["allowed_options"] == [0, 1] and d["n_max_voters"] == 5
    assert PublicParams.from_dict(d) == p


def test_params_strict():
    d = _params().to_dict()
    for mut in (lambda x: x.pop("question"), lambda x: x.update(extra=1),
                lambda x: x.update(version="v2"), lambda x: x.update(group_id="otro"),
                lambda x: x.update(generator=base_mul(Scalar.from_int(2)).to_hex()),
                lambda x: x.update(n_max_voters=0), lambda x: x.update(n_max_voters=21),
                lambda x: x.update(n_max_voters=True), lambda x: x.update(allowed_options=[0, 2])):
        e = copy.deepcopy(d)
        mut(e)
        with pytest.raises(ValueError):
            PublicParams.from_dict(e)
    e = copy.deepcopy(d)
    e["public_key"] = "00" * 32
    with pytest.raises(InvalidElement):
        PublicParams.from_dict(e)


def test_ballot_roundtrip():
    b, _ = _ballot()
    d = b.to_dict()
    check_ballot_shape(d)
    assert Ballot.from_dict(d) == b
    pub = b.public()
    pd = pub.to_dict()
    assert pd["token_id"] == b.token.token_id and "token" not in pd
    check_published_shape(pd)
    assert PublishedBallot.from_dict(pd) == pub


def test_published_from_dict_strict():
    pd = _ballot()[0].public().to_dict()
    pd["x"] = "1"
    with pytest.raises(MalformedBallot):
        PublishedBallot.from_dict(pd)


def _mut(f):
    d = _ballot()[0].to_dict()
    f(d)
    return d


def test_shape_missing_key():
    for f in (lambda d: d.pop("proof"), lambda d: d["token"].pop("tag"),
              lambda d: d["ciphertext"].pop("beta"), lambda d: d["proof"].pop("s1")):
        with pytest.raises(MalformedBallot):
            check_ballot_shape(_mut(f))


def test_shape_extra_key():
    for f in (lambda d: d.update(x="1"), lambda d: d["token"].update(x="1"),
              lambda d: d["ciphertext"].update(x="1"), lambda d: d["proof"].update(x="1")):
        with pytest.raises(MalformedBallot):
            check_ballot_shape(_mut(f))


@pytest.mark.parametrize("bad", [123, None, [1], True])
def test_shape_wrong_type(bad):
    for f in (lambda d: d["ciphertext"].update(alpha=bad), lambda d: d.update(timestamp=bad),
              lambda d: d["token"].update(secret=bad), lambda d: d["proof"].update(c0=bad)):
        with pytest.raises(MalformedBallot):
            check_ballot_shape(_mut(f))


def test_shape_uppercase_hex():
    def up(d):
        d["ciphertext"]["alpha"] = "AB" * 32
    with pytest.raises(MalformedBallot):
        check_ballot_shape(_mut(up))
    def up2(d):
        d["token"]["token_id"] = d["token"]["token_id"][:-1] + "A"
    with pytest.raises(MalformedBallot):
        check_ballot_shape(_mut(up2))


def test_shape_bad_version_group_election_timestamp():
    for f in (lambda d: d.update(version="v2"), lambda d: d.update(group_id="x"),
              lambda d: d["token"].update(version="v2"), lambda d: d.update(election_id="XYZ"),
              lambda d: d.update(timestamp=""), lambda d: d["token"].update(token_id="ab" * 31)):
        with pytest.raises(MalformedBallot):
            check_ballot_shape(_mut(f))


def test_shape_not_dict():
    for x in (None, [], "s", 5):
        with pytest.raises(MalformedBallot):
            check_ballot_shape(x)
        with pytest.raises(MalformedBallot):
            check_published_shape(x)


def test_published_shape_rejects_token():
    with pytest.raises(MalformedBallot):
        check_published_shape(_ballot()[0].to_dict())
    with pytest.raises(MalformedBallot):
        check_ballot_shape(_ballot()[0].public().to_dict())


def test_ciphertext_hash_stable():
    b, _ = _ballot()
    ct = b.ciphertext
    exp = sha256_hex(canonical_bytes({"alpha": ct.alpha.to_hex(), "beta": ct.beta.to_hex()}))
    assert ciphertext_hash(ct) == exp == ciphertext_hash(ct)


def test_expediente_roundtrip():
    b, p = _ballot()
    ex = Expediente(p, 3, [b.token.token_id], [b.public()], b.ciphertext, 1, utc_now_iso(), "cd" * 64)
    d = ex.to_dict()
    assert d["signature"] == "cd" * 64 and "signature" not in ex.body_dict()
    assert ex.signing_bytes() == canonical_bytes(ex.body_dict())
    assert Expediente.from_dict(d) == ex
    for f in (lambda x: x.update(extra=1), lambda x: x.pop("signature"),
              lambda x: x.update(declared_result=True), lambda x: x.update(tokens_issued="3")):
        e = copy.deepcopy(d)
        f(e)
        with pytest.raises(ValueError):
            Expediente.from_dict(e)


def test_utc_now_iso():
    assert utc_now_iso().endswith("+00:00")
