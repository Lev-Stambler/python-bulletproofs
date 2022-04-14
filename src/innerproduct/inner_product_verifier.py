"""Contains classes for the prover of an inner-product argument"""

from fastecdsa.curve import secp256k1, Curve
from sympy import Point
from src.pippenger.group import EC
from src.utils.cairo_constants import PROOF_VAR_NAME

from src.utils.transcript import Transcript
from src.utils.utils import mod_hash, point_to_b64, ModP, to_cairo_big_int
from src.pippenger import Pipsecp256k1

SUPERCURVE: Curve = secp256k1


class Proof1:
    """Proof class for Protocol 1"""

    def __init__(self, u_new, P_new, proof2, transcript):
        self.u_new = u_new
        self.P_new = P_new
        self.proof2 = proof2
        self.transcript = transcript


class Verifier1:
    """Verifier class for Protocol 1"""

    def __init__(self, g, h, u, P, c, proof1, prime=None):
        self.g = g
        self.h = h
        self.u = u
        self.P = P
        self.c = c
        self.proof1 = proof1
        self.prime = SUPERCURVE.q if prime is None else prime

    def assertThat(self, expr: bool):
        """Assert that expr is truthy else raise exception"""
        if not expr:
            raise Exception("Proof invalid")

    def verify_transcript(self):
        """Verify a transcript to assure Fiat-Shamir was done properly"""
        lTranscript = self.proof1.transcript
        self.assertThat(
            lTranscript[1]
            == Transcript.digest_to_hash(lTranscript[:1], self.prime)
        )

    def verify(self):
        """Verifies the proof given by a prover. Raises an execption if it is invalid"""
        self.verify_transcript()

        lTranscript = self.proof1.transcript
        x = lTranscript[1]
        x = ModP(x, self.prime)
        self.assertThat(self.proof1.P_new == self.P + (x * self.c) * self.u)
        self.assertThat(self.proof1.u_new == x * self.u)

        Verif2 = Verifier2(
            self.g, self.h, self.proof1.u_new, self.proof1.P_new, self.proof1.proof2
        )

        return Verif2.verify()


class Proof2:
    """Proof class for Protocol 2"""

    def __init__(self, a: ModP, b: ModP, xs: list[ModP], Ls: list[ModP], Rs: list[ModP], transcript: Transcript, start_transcript: int = 0, prime=None):
        self.a = a
        self.b = b
        self.xs = xs
        self.Ls = Ls
        self.Rs = Rs
        self.transcript = transcript
        self.start_transcript = (
            start_transcript
        )  # Start of transcript to be used if Protocol 2 is run in Protocol 1

    def convert_to_cairo(self, ids, memory, segments, n_elems):
        """
           Convert the transcript into a cairo so that the verifier can 
           check the proof
        """
        a0, a1, a2 = to_cairo_big_int(self.a.x)
        b0, b1, b2 = to_cairo_big_int(self.b.x)
        ids.proof_innerprod_2.a.d0 = a0
        ids.proof_innerprod_2.a.d1 = a1
        ids.proof_innerprod_2.a.d2 = a2

        ids.proof_innerprod_2.b.d0 = b0
        ids.proof_innerprod_2.b.d1 = b1
        ids.proof_innerprod_2.b.d2 = b2

        ids.proof_innerprod_2.n = n_elems

        Transcript.convert_to_cairo(ids, memory, segments, self.transcript)
        # self.transcript.convert_to_cairo()

        # ids[PROOF_VAR_NAME]

    # def convert_to_cairo(ids, memory, segments, digest: list):
    #     """
    #        Convert the transcript into a cairo so that the verifier can
    #        check the transcript
    #     """
    #     felt_list = Transcript.digest_to_int_list(digest[1:])

    #     ids.n_rounds = 10
    #     ids.transcript_seed = digest[0]
    #     #ids[TRANSCRIPT_LEN_NAME] = len(felt_list)
    #     ids.transcript_entries = transcript_entries = segments.add()
    #     for i, val in enumerate(felt_list):
    #         memory[transcript_entries + i] = val

    #     pass


class Verifier2:
    """Verifier class for Protocol 2"""

    def __init__(self, g, h, u, P, proof: Proof2, prime=None):
        self.g = g
        self.h = h
        self.prime = SUPERCURVE.q if prime is None else prime
        self.u = u
        self.P = P
        self.proof = proof

    def assertThat(self, expr):
        """Assert that expr is truthy else raise exception"""
        if not expr:
            raise Exception("Proof invalid")

    def get_ss(self, xs):
        """See page 15 in paper"""
        n = len(self.g)
        log_n = n.bit_length() - 1
        ss = []
        for i in range(1, n + 1):
            tmp = ModP(1, self.prime)
            for j in range(0, log_n):
                b = 1 if bin(i - 1)[2:].zfill(log_n)[j] == "1" else -1
                tmp *= xs[j] if b == 1 else xs[j].inv()
            ss.append(tmp)
        return ss

    def verify_transcript(self):
        """Verify a transcript to assure Fiat-Shamir was done properly"""
        init_len = self.proof.start_transcript
        print((len(self.proof.transcript) -1 ) // 3)
        n = len(self.g)
        log_n = n.bit_length() - 1
        Ls = self.proof.Ls
        Rs = self.proof.Rs
        xs = self.proof.xs
        lTranscript = self.proof.transcript
        for i in range(log_n):
            self.assertThat(lTranscript[init_len + i * 3] == Ls[i])
            self.assertThat(lTranscript[init_len + i * 3 + 1] == Rs[i])
            self.assertThat(
                xs[i]
                == lTranscript[init_len + i * 3 + 2]
                ==
                Transcript.digest_to_hash(
                    lTranscript[: init_len + i * 3 + 2],
                    self.prime,
                )
            )

    def verify(self):
        """Verifies the proof given by a prover. Raises an execption if it is invalid"""
        self.verify_transcript()

        proof = self.proof
        Pip = Pipsecp256k1
        ss = self.get_ss(self.proof.xs)
        LHS = Pip.multiexp(
            self.g + self.h + [self.u],
            [proof.a * ssi for ssi in ss]
            + [proof.b * ssi.inv() for ssi in ss]
            + [proof.a * proof.b],
        )
        RHS = self.P + Pip.multiexp(
            proof.Ls + proof.Rs,
            [xi ** 2 for xi in proof.xs] + [xi.inv() ** 2 for xi in proof.xs],
        )

        print("PY X", LHS.x)
        print("PY Y", RHS.y)

        self.assertThat(LHS == RHS)
        print("OK")
        return True
