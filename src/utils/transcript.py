import base64

from src.utils.cairo_constants import TRANSCRIPT_VAR_NAME

from .utils import in_cairo_hint, mod_hash, point_to_b64


class Transcript:
    """
    Transcript class.
    Contains all parameters used to generate randomness using Fiat-Shamir
    Separate every entity by a '&'. 
    """

    def __init__(self, seed=b""):
        self.digest = base64.b64encode(seed) + b"&"

    def convert_to_cairo(self):
        """
           Convert the transcript into a cairo so that the verifier can 
           check the transcript
        """
        if in_cairo_hint() == False:
            raise Exception("Must be in a cairo hint")
        # ids[TRANSCRIPT_VAR_NAME] = 
        pass

    def add_point(self, g):
        """Add an elliptic curve point to the transcript"""
        self.digest += point_to_b64(g)
        self.digest += b"&"

    def add_list_points(self, gs):
        """Add a list of elliptic curve point to the transcript"""
        for g in gs:
            self.add_point(g)

    def add_number(self, x):
        """Add a number to the transcript"""
        self.digest += str(x).encode()
        self.digest += b"&"

    def get_modp(self, p):
        """Generate a number as the hash of the digest"""
        return mod_hash(self.digest, p)
