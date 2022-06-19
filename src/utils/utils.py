"""Contains various utilities"""

from hashlib import blake2s
from typing import List, Union


from fastecdsa.point import Point



CAIRO_PRIME = 2 ** 251 + 17 * 2 ** 192 + 1


def egcd(a, b):
    """Extended euclid algorithm"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


class ModP:
    """Class representing an integer mod p"""

    def __init__(self, x, p):
        if isinstance(x, int):
            self.x = x
        else:
            self.x = x.x
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
            return ModP((self.x % self.p) * (y % self.p), self.p)
        if isinstance(y, Point):
            return self.x * y
        assert self.p == y.p
        return ModP(((self.x % self.p) * (y.x % y.p)) % self.p, self.p)

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
        if isinstance(other, ModP):
            return self.x % other.x
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
        if isinstance(y, int):
            y = ModP(y, self.p)
        return (self.p == y.p) and (self.x % self.p == y.x % self.p)

    def __str__(self):
        return str(self.x)

    def __repr__(self):
        return str(self.x)


def mod_hash(msg: Union[bytes, list[int]], p: int, p_computation=CAIRO_PRIME) -> ModP:
    """
    Takes a message and a prime and returns a hash in ModP. Computation is done in p_computation if specified.
    Because a random number modulo a prime retains its "randomness" property
    (i.e. uniform probability distribution over F_p), we can compute the hash in the prime CAIRO_PRIME,
    and return the result mod a smaller prime p
    This is done for ease of computation in Cairo
    """
    digest = None
    p_computation = p if p_computation is None else p_computation
    #assert p_computation >= p
    if isinstance(msg, bytes):
        digest = blake2s(msg).digest()
    else:
        _bytes = bytes([])
        for e in msg:
            # TODO: this can probably be far more efficient by not having padded words
            # this also means that you will have to preprocess the input on cairo side...
            _bytes += e.to_bytes(8 * 4, "little")
        # _bytes = [int.from_bytes(_bytes[i:i+1], 'little')
        #           for i in range(len(_bytes))]
        digest = blake2s(_bytes).digest()

    int_list = []
    digest = list(digest)
    # Digest is a list of 8 32 bit words
    for pos in range(0, len(digest), 4):
        int_list += [int.from_bytes(digest[pos: pos + 4], 'little')]
    ret = ModP(0, p_computation)
    for i in int_list:
        ret = (ret * ModP(2 ** 32, p_computation)) + ModP(i, p_computation)
    return ModP(ret.x, p)

def inner_product(a: List[ModP], b: List[ModP]) -> ModP:
    """Inner-product of vectors in Z_p"""
    assert len(a) == len(b)
    return sum([ai * bi for ai, bi in zip(a, b)], ModP(0, a[0].p))


def set_ec_points(ids, segments, memory, name: str, ps: list[Point]):
    points_cairo = segments.add()
    ids.get_or_set_value(name, points_cairo)
    for i, p in enumerate(ps):
        memory[points_cairo + 2 * i + 0] = p.x
        memory[points_cairo + 2 * i + 1] = p.y