#!/usr/bin/env python3
#
# Applied Cryptography 2020 @ ETHZ
# Loris Reiff
#
from itertools import cycle
from base64 import b64encode
import os
import string

def xor(data, key):
    out = bytearray()
    for (b, k) in zip(data, cycle(key)):
        out.append(b ^ k)
    return out


def otp(data):
    r = os.urandom(len(data))
    return xor(data, r), r

if __name__ == '__main__':
    import sys

    if (len(sys.argv) < 2):
        print("./prog TEXT")
        sys.exit()

    data = sys.argv[1].encode()
    c, k = otp(data)
    print("Key:", k.hex())
    print("Ciphertext:", c.hex())


