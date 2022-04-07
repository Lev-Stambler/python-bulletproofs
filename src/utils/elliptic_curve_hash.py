from fastecdsa.point import Point
from fastecdsa.keys import gen_keypair
from fastecdsa.curve import Curve
from fastecdsa.util import mod_sqrt
from hashlib import sha256, md5


# TODO: think of something better...
def elliptic_hash_P224(msg: bytes, CURVE: Curve):
    d, Q = gen_keypair(CURVE)
    return Q

    p = CURVE.p
    i = 0
    while True:
        i += 1
        prefixed_msg = str(i).encode() + msg
        h = sha256(prefixed_msg).hexdigest()
        x = int(h, 16) % p
        if x >= p:
            continue

        y_sq = (x ** 3 + CURVE.a * x + CURVE.b) % p
        y = mod_sqrt(y_sq, p)[0]
        
        if CURVE.is_point_on_curve((x, y)):
            b = int(md5(prefixed_msg).hexdigest(), 16) % 2
            return Point(x, y, CURVE) if b else Point(x, p - y, CURVE)

# Takes in a curve of order ~ 2 ^ 252
def _elliptic_hash_secp256k1(msg: bytes, CURVE: Curve):
    p = CURVE.p
    i = 0
    while True:
        i += 1
        prefixed_msg = str(i).encode() + msg
        h = sha256(prefixed_msg).hexdigest()
        x = int(h, 16)
        if x >= p:
            continue

        y_sq = (x ** 3 + CURVE.a * x + CURVE.b) % p
        print(type(y_sq), type(p))
        y = mod_sqrt(y_sq, p)[0]
        
        if CURVE.is_point_on_curve((x, y)):
            b = int(md5(prefixed_msg).hexdigest(), 16) % 2
            return Point(x, y, CURVE) if b else Point(x, p - y, CURVE)

