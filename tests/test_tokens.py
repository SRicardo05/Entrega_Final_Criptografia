import dataclasses

from evoting.crypto.tokens import Token, issue_token, verify_token

KEY = b"k" * 32
EID = "0123456789abcdef"


def test_token_roundtrip_and_verify():
    t = issue_token(KEY, EID)
    assert len(t.token_id) == 32 and len(t.secret) == 64 and len(t.tag) == 64
    assert Token.from_dict(t.to_dict()) == t
    assert t.to_dict()["version"] == "v1"
    assert verify_token(KEY, t)


def test_token_forged_tag():
    t = issue_token(KEY, EID)
    assert not verify_token(KEY, dataclasses.replace(t, tag="0" * 64))


def test_token_other_key():
    assert not verify_token(b"x" * 32, issue_token(KEY, EID))


def test_token_tampered_id():
    t = issue_token(KEY, EID)
    assert not verify_token(KEY, dataclasses.replace(t, token_id="0" * 32))


def test_token_other_election():
    t = issue_token(KEY, EID)
    assert not verify_token(KEY, dataclasses.replace(t, election_id="f" * 16))
