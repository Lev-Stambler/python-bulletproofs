from fastecdsa.curve import secp256k1

from .pippenger import Pippenger
from .group import EC

Pipsecp256k1 = Pippenger(EC(secp256k1))
Pip256k1 = Pippenger(EC(secp256k1))

__all__ = ["Pippenger", "EC", "Pipsecp256k1"]