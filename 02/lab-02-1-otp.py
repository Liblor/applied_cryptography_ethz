#!/usr/bin/env python3
#
# Applied Cryptography 2020 @ ETHZ
# Loris Reiff
#
from itertools import cycle
from base64 import b64encode
import string

def xor(data, key):
    out = bytearray()
    for (b, k) in zip(data, cycle(key)):
        out.append(b ^ k)
    return out

if __name__ == '__main__':
    c1 = "c29844c29fc280164017c291c390c3bcc2aa09c392c2a17322c2994753c38a3a"\
         "7bc2885ec3b04059c38724c2b4c2b7c2b6c391c280c3a0c2b60dc296c2bcc3b0"\
         "43c3a8c282c3ab683e45c2ba35c396c3821d64c28bc28bc297c2a8c29b7bc3a7"\
         "c2b4782c40c3adc2834f51c28c4645c28dc385c389"
    otp = "c825e6a0782f37fcb992ce29a6ce5356f12273ae5308fc3f9e3479b34cc1d9d2"\
          "b4f2cc964ff3dd853791a28d015229c915beab6e44e3eef6ccbb0c8ec0100c37"\
          "82ed2b34fe6a65efaab0"
    c1_b = bytes.fromhex(c1).decode("utf-8")
    c1_b = [ord(c) for c in c1_b]
    otp_b = bytes.fromhex(otp)
    plaintext = xor(c1_b, otp_b)
    print(plaintext.decode())
