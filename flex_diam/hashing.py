"""flex_diam.hashing — the hash function H(.) and the "||" concatenation.

The paper writes H(a || b || ...) with H a collision-resistant hash. Here H is
SHA-256 and "||" is an unambiguous encoding: every component is length-prefixed
(4-byte big-endian) before hashing, so ("ab","c") and ("a","bc") never collide.

`field_of_digest()` / `field_of_str()` map a value into the BN254 scalar field
(248 bits) so it can be used as a signal of the Groth16 circuit.
"""

from __future__ import annotations

import hashlib

FIELD_BYTES = 31  # 248 bits < BN254 scalar field modulus (~2^254)


def _b(x) -> bytes:
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return x.encode("utf-8")
    if isinstance(x, bool):
        raise TypeError("bool is not hashable here; encode it explicitly")
    if isinstance(x, int):
        return str(x).encode("ascii")
    if isinstance(x, (tuple, list)):
        return encode(*x)
    raise TypeError(f"cannot encode {type(x).__name__}")


def encode(*parts) -> bytes:
    """Unambiguous encoding of a || b || ... (length-prefixed components)."""
    out = bytearray()
    for p in parts:
        pb = _b(p)
        out += len(pb).to_bytes(4, "big") + pb
    return bytes(out)


def H(*parts) -> bytes:
    """H(a || b || ...) -> 32 bytes."""
    return hashlib.sha256(encode(*parts)).digest()


def Hhex(*parts) -> str:
    return H(*parts).hex()


def field_of_digest(digest: bytes) -> int:
    """Field element of a 32-byte digest (e.g. rho): its first 31 bytes."""
    if len(digest) != 32:
        raise ValueError("expected a 32-byte digest")
    return int.from_bytes(digest[:FIELD_BYTES], "big")


def field_of_str(s: str) -> int:
    """Field element of an identifier or attribute name: SHA-256, first 31 bytes."""
    return field_of_digest(hashlib.sha256(s.encode("utf-8")).digest())
