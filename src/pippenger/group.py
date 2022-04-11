from abc import ABC, abstractmethod

from src.utils.utils import to_cairo_big_int

from src.utils.utils import ModP
from fastecdsa.curve import Curve
from fastecdsa.point import Point


class Group(ABC):
    def __init__(self, unit, order):
        self.unit = unit
        self.order = order

    @abstractmethod
    def mult(self, x, y):
        pass

    def square(self, x):
        return self.mult(x, x)


class MultIntModP(Group):
    def __init__(self, p, order):
        Group.__init__(self, ModP(1, p), order)

    def mult(self, x, y):
        return x * y


class EC(Group):
    def __init__(self, curve: Curve):
        Group.__init__(self, curve.G.IDENTITY_ELEMENT, curve.q)

    def mult(self, x, y):
        return x + y

    def elem_to_cairo(p: Point) -> list[int]:
        """
            Take in an ec point and convert it into a cairo struct of type `EcPoint`
            struct EcPoint:
                member x : BigInt3
                member y : BigInt3
            end
            @return a list of 6 felt elements
        """
        x = to_cairo_big_int(p.x)
        y = to_cairo_big_int(p.y)
        return list(x) + list(y)
        
