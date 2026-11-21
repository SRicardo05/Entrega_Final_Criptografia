from types import SimpleNamespace

import pytest

from evoting.protocol.authority import Authority
from evoting.storage.db import Store

try:
    from evoting.protocol.ballot_box import BallotBox
except ImportError:
    BallotBox = None


@pytest.fixture
def election():
    store = Store(":memory:")
    authority = Authority(store)
    params = authority.create_election("¿Aprueba la propuesta?", 20)
    tokens = authority.issue_tokens(params.election_id, 20)
    box = BallotBox(store) if BallotBox is not None else None
    yield SimpleNamespace(store=store, authority=authority, params=params, tokens=tokens, box=box)
    store.close()
