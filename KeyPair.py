# Created by Mate Vagner

import random

from secp256k1 import curve, scalar_mult

class KeyPair:
    def __init__(self):
        # Private key is d - a random number.
        self.PrivKey = random.randint(0, curve.n-1)
        # Public key is B = d * G
        self.PubKey = scalar_mult(self.PrivKey, curve.g)

    def GetPrivKey(self):
        return self.PrivKey

    def GetPubKey(self):
        return self.PubKey
