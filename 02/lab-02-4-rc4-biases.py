#!/usr/bin/env python3
#
# Applied Cryptography 2020 @ ETHZ
# Loris Reiff
#
import base64
import os
import numpy as np
from base64 import b64decode
from Crypto.Cipher import ARC4
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def encryption_oracle(plaintext, key):
    cipher = ARC4.new(key)
    return cipher.encrypt(plaintext)


if __name__ == '__main__':
    ptxt = b'T25lIERheSBZb3UgV2lsbCBUZWFjaCBNZSBUbyBMZXQgR28gb2YgTXkgRmVhcnM='
    p = b64decode(ptxt)

    cnt = [0] * 256

    for i in range(600000):
        a = encryption_oracle(p, get_random_bytes(16))
        b = a[1]
        cnt[b] += 1


    print("Second char:", chr(np.argmax(cnt)))
