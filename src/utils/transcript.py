from fastecdsa.point import Point
from src.pippenger.group import EC

from .utils import ModP, mod_hash, point_to_b64, point_to_cairo_ec_point, to_cairo_big_int


# Transcript now uses a mod hash to separate and hash
class Transcript:
    """
    Transcript class.
    Contains all parameters used to generate randomness using Fiat-Shamir
    Every entity is an integer and an element in a list
    """

    def __init__(self, seed=0):
        self.digest = [seed]

    def convert_to_cairo(ids, memory, segments, digest: list):
        """
           Convert the transcript into a cairo so that the verifier can 
           check the transcript
        """
        felt_list = Transcript.digest_to_int_list(digest[1:])

        ids.transcript = transcript = segments.add()

        # set the seed
        memory[transcript] = digest[0]
        # set number of entries to be the number of points/ mod p ints - 1 / 3
        # This is because there is 1 entry for the seed, and for every L, R, x,
        # there is one entry
        assert (len(digest) - 1) % 3 == 0
        memory[transcript + 1] = (len(digest) - 1) // 3

        ids.transcript_entries = transcript_entries = segments.add()

        # Set the transcript
        memory[transcript + 2] = transcript_entries

        #ids[TRANSCRIPT_LEN_NAME] = len(felt_list)
        for i, val in enumerate(felt_list):
            memory[transcript_entries + i] = val

    def add_point(self, g: Point):
        """Add an elliptic curve point to the transcript"""
        self.digest += [g]
        # Up next is get the verifier to change the way it checks the transcript for Python
        # (helps with testing purposes...)

    def add_list_points(self, gs):
        """Add a list of elliptic curve point to the transcript"""
        for g in gs:
            self.add_point(g)

    def add_number(self, x):
        """Add a number to the transcript"""
        self.digest += [x]

    def get_modp(self, p):
        return Transcript.digest_to_hash(self.digest, p)

    def digest_to_hash(digest: list, p):
        """Generate a number as the hash of the digest"""
        int_list = Transcript.digest_to_int_list(digest)
        return mod_hash(int_list, p)

    def digest_to_int_list(digest: list) -> list[int]:
        int_list = []
        for i in digest:
            if isinstance(i, Point):
                int_list += EC.elem_to_cairo(i)
            elif isinstance(i, ModP):
                int_list += list(to_cairo_big_int(i.x % i.p))
            else:
                int_list += [i]

        return int_list
