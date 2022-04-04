import base64

from fastecdsa.point import Point
from src.pippenger.group import EC

from src.utils.cairo_constants import TRANSCRIPT_VAR_NAME

from .utils import in_cairo_hint, mod_hash, point_to_b64, point_to_cairo_ec_point


# Transcript now uses a mod hash to separate and hash
class Transcript:
    """
    Transcript class.
    Contains all parameters used to generate randomness using Fiat-Shamir
    Every entity is an integer and an element in a list
    """

    def __init__(self, seed=0):
        self.digest = [seed]

    def convert_to_cairo(self):
        """
           Convert the transcript into a cairo so that the verifier can 
           check the transcript
        """
        if in_cairo_hint() == False:
            raise Exception("Must be in a cairo hint")
        # ids[TRANSCRIPT_VAR_NAME] = 
        pass

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
        int_list = []
        for i in digest:
            if isinstance(i, Point):
                int_list += EC.elem_to_cairo(i)
            else:
                int_list += [i]
        # TODO: remove bytearray once converted
        return mod_hash(bytearray(str.encode(str(int_list))), p)

