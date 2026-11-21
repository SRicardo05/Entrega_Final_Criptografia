"""Envoltorio del grupo Ed25519 de orden primo L (subgrupo principal), sobre PyNaCl."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

import nacl.bindings as nb

L = 2**252 + 27742317777372353535851937790883648493
GROUP_ID = "ed25519-primeorder-v1"


class InvalidElement(ValueError):
    """Punto o escalar inválido."""


_HEX64 = re.compile(r"[0-9a-f]{64}")


def _check_hex64(s, what: str) -> bytes:
    if not isinstance(s, str) or _HEX64.fullmatch(s) is None:
        raise InvalidElement(f"Hex de {what} inválido: se esperan 64 caracteres hex en minúscula")
    return bytes.fromhex(s)


@dataclass(frozen=True)
class Scalar:
    value: int

    @staticmethod
    def from_int(n: int) -> "Scalar":
        return Scalar(n % L)

    @staticmethod
    def from_bytes(b: bytes) -> "Scalar":
        if len(b) != 32:
            raise InvalidElement("El escalar debe tener 32 bytes")
        v = int.from_bytes(b, "little")
        if v >= L:
            raise InvalidElement("Escalar no canónico (>= L)")
        return Scalar(v)

    @staticmethod
    def from_hex(s: str) -> "Scalar":
        return Scalar.from_bytes(_check_hex64(s, "escalar"))

    def to_bytes(self) -> bytes:
        return (self.value % L).to_bytes(32, "little")

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def random() -> "Scalar":
        while True:
            v = int.from_bytes(os.urandom(64), "little") % L
            if v != 0:
                return Scalar(v)

    def __add__(self, o: "Scalar") -> "Scalar":
        return Scalar((self.value + o.value) % L)

    def __sub__(self, o: "Scalar") -> "Scalar":
        return Scalar((self.value - o.value) % L)

    def __mul__(self, o: "Scalar") -> "Scalar":
        return Scalar((self.value * o.value) % L)

    def __neg__(self) -> "Scalar":
        return Scalar((-self.value) % L)


@dataclass(frozen=True)
class Point:
    data: bytes

    @staticmethod
    def decode(b: bytes) -> "Point":
        if len(b) != 32:
            raise InvalidElement("El punto debe tener 32 bytes")
        if not nb.crypto_core_ed25519_is_valid_point(b):
            raise InvalidElement("Punto inválido, de orden pequeño o fuera del subgrupo")
        return Point(bytes(b))

    @staticmethod
    def from_hex(s: str) -> "Point":
        return Point.decode(_check_hex64(s, "punto"))

    def to_hex(self) -> str:
        return self.data.hex()

    def __add__(self, o: "Point") -> "Point":
        if self == IDENTITY:
            return o
        if o == IDENTITY:
            return self
        return Point(nb.crypto_core_ed25519_add(self.data, o.data))

    def __sub__(self, o: "Point") -> "Point":
        if o == IDENTITY:
            return self
        if self == o:
            return IDENTITY
        return Point(nb.crypto_core_ed25519_sub(self.data, o.data))

    def __mul__(self, k: Scalar) -> "Point":
        if k.value % L == 0 or self == IDENTITY:
            return IDENTITY
        return Point(nb.crypto_scalarmult_ed25519_noclamp(k.to_bytes(), self.data))


IDENTITY = Point(b"\x01" + b"\x00" * 31)
G = Point(nb.crypto_scalarmult_ed25519_base_noclamp((1).to_bytes(32, "little")))


def base_mul(k: Scalar) -> Point:
    if k.value % L == 0:
        return IDENTITY
    return Point(nb.crypto_scalarmult_ed25519_base_noclamp(k.to_bytes()))
