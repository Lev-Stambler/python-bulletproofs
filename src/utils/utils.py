"""Contains various utilities"""

from sympy import Mod
from hashlib import blake2s
from typing import List, Union
import base64

from fastecdsa.point import Point
from fastecdsa.curve import secp256k1
from fastecdsa.util import mod_sqrt

from src.utils.uint256 import Uint256

CURVE = secp256k1
BYTE_LENGTH = CURVE.q.bit_length() // 8

CAIRO_BIG_INT_BASE = 2 ** 86


# Take in a point and return 6 numbers d_x_0, d_x_1, d_x_2, d_y_0, d_y_1, d_y_2,
# The first three representing x's big int 3 coefficients and the second three
# representing y big int 3 coefficients
def point_to_cairo_ec_point(p: Point):
    pass


def egcd(a, b):
    """Extended euclid algorithm"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def in_cairo_hint():
    try:
        ids
        return True
    except NameError:
        return False


class ModP:
    """Class representing an integer mod p"""

    def __init__(self, x, p):
        self.x = x
        self.p = p

    def __add__(self, y):
        if isinstance(y, int):
            return ModP(self.x + y, self.p)
        assert self.p == y.p
        return ModP((self.x + y.x) % self.p, self.p)

    def __radd__(self, y):
        return self + y

    def __mul__(self, y):
        if isinstance(y, int):
            return ModP(self.x * y, self.p)
        if isinstance(y, Point):
            return self.x * y
        assert self.p == y.p
        return ModP((self.x * y.x) % self.p, self.p)

    def __sub__(self, y):
        if isinstance(y, int):
            return ModP((self.x - y) % self.p, self.p)
        assert self.p == y.p
        return ModP((self.x - y.x) % self.p, self.p)

    def __rsub__(self, y):
        return -(self - y)

    def __pow__(self, n):
        return ModP(pow(self.x, n, self.p), self.p)

    def __mod__(self, other):
        return self.x % other

    def __neg__(self):
        return ModP(self.p - self.x, self.p)

    def inv(self):
        """Returns the modular inverse"""
        g, a, _ = egcd(self.x, self.p)
        if g != 1:
            raise Exception("modular inverse does not exist")
        else:
            return ModP(a % self.p, self.p)

    def __eq__(self, y):
        return (self.p == y.p) and (self.x % self.p == y.x % self.p)

    def __str__(self):
        return str(self.x)

    def __repr__(self):
        return str(self.x)


# def cairo_keccak(data: list[int]) -> Uint256:
#     data, length = data, len(data)

#     keccak_input = bytearray()
#     for word_i, byte_i in enumerate(range(0, length, 16)):
#         word = data[word_i]
#         n_bytes = min(16, length - byte_i)
#         assert 0 <= word < 2 ** (8 * n_bytes)
#         keccak_input += word.to_bytes(n_bytes, 'big')

#     hashed = keccak(keccak_input)
#     high = int.from_bytes(hashed[:16], 'big')
#     low = int.from_bytes(hashed[16:32], 'big')
#     return Uint256(low, high)

# TODO: convert to a different type of hash (like pederson...)


def mod_hash(msg: Union[bytes, list[int]], p: int, non_zero: bool = True) -> ModP:
    """Takes a message and a prime and returns a hash in ModP"""
    digest = None
    if isinstance(msg, bytes):
        digest = blake2s(msg).digest()
    else:
        _bytes = bytes([])
        for e in msg:
            _bytes += e.to_bytes(4, "little")
        digest = blake2s(_bytes).digest() 

    int_list = []
    digest = list(digest)
    # Digest is a list of 8 32 bit words
    for pos in range(0, len(digest), 4):
        int_list += [int.from_bytes(digest[pos: pos + 4], 'little')]
    
    # TODO: this step feels sketch...
    ret = 0
    for i in int_list:
        ret = (ret << 32) + i
    return ModP(ret, p)


def point_to_bytes(g: Point) -> bytes:
    """Takes an EC point and returns the compressed bytes representation"""
    if g == Point.IDENTITY_ELEMENT:
        return b"\x00"
    x_enc = g.x.to_bytes(BYTE_LENGTH, "big")
    prefix = b"\x03" if g.y % 2 else b"\x02"
    return prefix + x_enc


def point_to_b64(g: Point) -> bytes:
    """Takes an EC point and returns the base64 compressed bytes representation"""
    return base64.b64encode(point_to_bytes(g))


def b64_to_point(s: bytes) -> Point:
    """Takes a base64 compressed bytes representation and returns the corresponding point"""
    return bytes_to_point(base64.b64decode(s))


def bytes_to_point(b: bytes) -> Point:
    """Takes a compressed bytes representation and returns the corresponding point"""
    if b == 0:
        return Point.IDENTITY_ELEMENT
    p = CURVE.p
    yp, x_enc = b[0], b[1:]
    yp = 0 if yp == 2 else 1
    x = int.from_bytes(x_enc, "big")
    y = mod_sqrt((x ** 3 + CURVE.a * x + CURVE.b) % p, p)[0]
    if y % 2 == yp:
        return Point(x, y, CURVE)
    else:
        return Point(x, p - y, CURVE)


def inner_product(a: List[ModP], b: List[ModP]) -> ModP:
    """Inner-product of vectors in Z_p"""
    assert len(a) == len(b)
    return sum([ai * bi for ai, bi in zip(a, b)], ModP(0, a[0].p))


def to_cairo_big_int(a: int) -> tuple[int, int, int]:
    """
        Takes in an int and returns a big int tuple of (d0, d1, d2)
        where d0 + BASE * d1 + BASE**2 * d2
        struct BigInt3:
            member d0 : felt
            member d1 : felt
            member d2 : felt
        end
    """
    d2 = a // CAIRO_BIG_INT_BASE ** 2
    d1 = (a - d2 * CAIRO_BIG_INT_BASE ** 2) // CAIRO_BIG_INT_BASE
    d0 = (a - d1 * CAIRO_BIG_INT_BASE - d2 * CAIRO_BIG_INT_BASE ** 2)
    return d0, d1, d2
