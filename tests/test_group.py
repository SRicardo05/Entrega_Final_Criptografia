import nacl.bindings
import pytest

from evoting.crypto.group import (
    G, IDENTITY, L, InvalidElement, Point, Scalar, base_mul,
)

ORDER2 = bytes.fromhex("ec" + "ff" * 30 + "7f")      # (0,-1), orden 2
NONCANON = bytes.fromhex("ed" + "ff" * 30 + "7f")    # y = p, codificación no canónica


def test_base_point_valid():
    assert Point.decode(G.data) == G


def test_identity_rejected():
    with pytest.raises(InvalidElement):
        Point.decode(IDENTITY.data)


def test_small_order_rejected():
    with pytest.raises(InvalidElement):
        Point.decode(ORDER2)


def test_noncanonical_rejected():
    with pytest.raises(InvalidElement):
        Point.decode(NONCANON)


def test_mixed_order_rejected():
    mixed = nacl.bindings.crypto_core_ed25519_add(G.data, ORDER2)
    with pytest.raises(InvalidElement):
        Point.decode(mixed)


def test_wrong_length_rejected():
    with pytest.raises(InvalidElement):
        Point.decode(b"\x00" * 31)


def test_scalar_noncanonical():
    with pytest.raises(InvalidElement):
        Scalar.from_bytes(L.to_bytes(32, "little"))


def test_scalar_max_ok():
    assert Scalar.from_bytes((L - 1).to_bytes(32, "little")).value == L - 1


def test_mul_distributes():
    a, b = Scalar.random(), Scalar.random()
    assert base_mul(a + b) == base_mul(a) + base_mul(b)


def test_identity_laws():
    P = base_mul(Scalar.random())
    assert P + IDENTITY == P and P - P == IDENTITY and IDENTITY + P == P


def test_mul_by_zero_and_order():
    assert G * Scalar(0) == IDENTITY and base_mul(Scalar(L - 1)) + G == IDENTITY


def test_hex_roundtrip():
    P = base_mul(Scalar.random())
    assert Point.from_hex(P.to_hex()) == P and P.to_hex() == P.to_hex().lower()


@pytest.mark.parametrize("bad", [
    base_mul(Scalar.from_int(2)).to_hex().upper(), " " + G.to_hex(), G.to_hex() + "\n", 123, None, b"00" * 32, "",
])
def test_from_hex_strict_point(bad):
    with pytest.raises(InvalidElement):
        Point.from_hex(bad)


@pytest.mark.parametrize("bad", ["AB" * 32, " " + "01" * 32, "01" * 32 + " ", 123, None, "0" * 63])
def test_from_hex_strict_scalar(bad):
    with pytest.raises(InvalidElement):
        Scalar.from_hex(bad)
