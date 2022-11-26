# This is a ECDSA implementation and tester python script.
# Created by Mate Vagner

import sys

from KeyPair import KeyPair
from ECDSAWorker import ECDSAWorker

def test(msg):

    # Print for testing
    print(f"A's message: {msg}")

    # Generate a KeyPair for A and B
    keys_A = KeyPair()
    keys_B = KeyPair()
    # Generate a Worker
    AliceWorker = ECDSAWorker()
    BobWorker = ECDSAWorker()

    # Print for testing
    print("\nA's keys:")
    print(f"Private key: {keys_A.PrivKey}")
    print(f"Public key: {keys_B.PubKey}")
    print("\nB's keys:")
    print(f"Private key: {keys_B.PrivKey}")
    print(f"Public key: {keys_B.PubKey}")

    # A signs the message.
    [r_A, s_A] = AliceWorker.Sign(msg, keys_A.GetPrivKey())

    # Verify A's the message
    res_A = BobWorker.Verify(msg, r_A, s_A, keys_A.GetPubKey())

    # Print for testing
    print("\nA send the message for B:")
    if(res_A):
        print("Succesfull verification!\n")
    else:
        print("Verification error!\n")

    # Send back the message - B tells A he got it.
    [r_B, s_B] = BobWorker.Sign(msg, keys_B.GetPrivKey())

    # A verifies if B saw it.
    res_B = AliceWorker.Verify(msg, r_B, s_B, keys_B.GetPubKey())

    # Print for testing
    print("B got message from A:")
    if (res_A):
        print("Succesfull verification!")
    else:
        print("Verification error!")

# Run the test for first
if __name__ == '__main__':
    msg = "Csókolom, Ági van?"
    test(msg)
