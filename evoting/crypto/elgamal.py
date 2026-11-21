"""ElGamal exponencial sobre el grupo Ed25519 de orden primo."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from evoting.crypto.group import IDENTITY, G, Point, Scalar, base_mul


class DecryptionError(ValueError):
    """El valor descifrado queda fuera del rango [0, n_max]."""


@dataclass(frozen=True)
class Ciphertext:
    alpha: Point
    beta: Point

    def __add__(self, o: "Ciphertext") -> "Ciphertext":
        return Ciphertext(self.alpha + o.alpha, self.beta + o.beta)


def keygen() -> tuple[Scalar, Point]:
    x = Scalar.random()
    return x, base_mul(x)


def encrypt(h: Point, v: int, r: Scalar | None = None) -> tuple[Ciphertext, Scalar]:
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise ValueError("v debe ser un entero >= 0")
    if r is None:
        r = Scalar.random()
    alpha = base_mul(r)
    beta = base_mul(Scalar.from_int(v)) + h * r
    return Ciphertext(alpha, beta), r


def aggregate(cts: Iterable[Ciphertext]) -> Ciphertext:
    total = Ciphertext(IDENTITY, IDENTITY)
    for ct in cts:
        total = total + ct
    return total


def decrypt_aggregate(x: Scalar, ct: Ciphertext, n_max: int) -> int:
    if not isinstance(n_max, int) or isinstance(n_max, bool) or n_max < 0:
        raise ValueError("n_max debe ser un entero >= 0")
    target = ct.beta - ct.alpha * x
    point = IDENTITY
    for k in range(n_max + 1):
        if point == target:
            return k
        point = point + G
    raise DecryptionError("El resultado está fuera del rango esperado")
