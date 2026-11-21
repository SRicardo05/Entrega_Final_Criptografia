import random

import pytest

from evoting.crypto.elgamal import (
    Ciphertext,
    DecryptionError,
    aggregate,
    decrypt_aggregate,
    encrypt,
    keygen,
)
from evoting.crypto.group import IDENTITY


@pytest.mark.parametrize("n", range(1, 21))
def test_tally_all_sizes(n):
    x, h = keygen()
    votes = [random.randint(0, 1) for _ in range(n)]
    cts = [encrypt(h, v)[0] for v in votes]
    assert decrypt_aggregate(x, aggregate(cts), n) == sum(votes)


def test_tally_zero():
    x, h = keygen()
    cts = [encrypt(h, 0)[0] for _ in range(5)]
    assert decrypt_aggregate(x, aggregate(cts), 5) == 0


def test_tally_all_ones_20():
    x, h = keygen()
    cts = [encrypt(h, 1)[0] for _ in range(20)]
    assert decrypt_aggregate(x, aggregate(cts), 20) == 20


def test_empty_aggregate():
    x, _ = keygen()
    assert aggregate([]) == Ciphertext(IDENTITY, IDENTITY)
    assert decrypt_aggregate(x, aggregate([]), 0) == 0


def test_out_of_range_raises():
    x, h = keygen()
    cts = [encrypt(h, 1)[0] for _ in range(3)]
    with pytest.raises(DecryptionError):
        decrypt_aggregate(x, aggregate(cts), 2)


def test_randomized():
    _, h = keygen()
    assert encrypt(h, 1)[0] != encrypt(h, 1)[0]


def test_invalid_n_max():
    x, _ = keygen()
    with pytest.raises(ValueError):
        decrypt_aggregate(x, aggregate([]), -1)
