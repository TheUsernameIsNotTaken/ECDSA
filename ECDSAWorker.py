#Created by Mate Vagner

import random
import hashlib
import libnum

from secp256k1 import curve, scalar_mult, point_add

class ECDSAWorker:

    def Sign(self, msg, privkey):
        # Use the message hash for signing.
        h = int(hashlib.sha256(msg.encode()).hexdigest(), 16)
        # k is our short-life signature key.
        k = random.randint(0, curve.n - 1)
        # Get R = k * G. This also gets us r = Rx mod q
        R = scalar_mult(k, curve.g)
        r = R[0] % curve.n
        # Get s = (H(m) + d * r) * inv(k) mod q
        k_inv = libnum.invmod(k, curve.n)
        s = ((h + privkey * r) * k_inv) % curve.n
        # m message generates (r, s) for signature.
        return [r, s]

    def Verify(self, msg, r, s, pubkey):
        # Get h = H(m).
        h = int(hashlib.sha256(msg.encode()).hexdigest(), 16)
        # Get w = inv(s) mod q
        w = libnum.invmod(s, curve.n)
        # Get u1 = w * H(m) mod q and u2 = w * r mod q.
        u1=(h*w) % curve.n
        u2=(r*w) % curve.n
        # Get P = u1*G + u2*B
        P = point_add(scalar_mult(u1, curve.g), scalar_mult(u2, pubkey))
        return P[0] == (r % curve.n)
