class Uint256():
    def __init__(self, low, high) -> None:
        self.high = high
        self.low = high

    def to_int(self) -> int:
        return 2 ** 32 * self.high + self.low

    def to_cairo_uint_256(self) -> list[int]:
        """
            For reference, see https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/cairo/common/uint256.cairo,
            Returns a list of numbers for 
            # Represents an integer in the range [0, 2^256).
            struct Uint256:
                    # The low 128 bits of the value.
                    member low : felt
                    # The high 128 bits of the value.
                    member high : felt
            end
        """
        return [self.low, self.high]
