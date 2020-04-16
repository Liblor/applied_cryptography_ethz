#!/usr/bin/env python3
#
# Applied Cryptography 2020 @ ETHZ
# Loris Reiff
#
import hashlib
import hmac
from math import ceil


def hmac_sha256(key, data):
    """
    Helper function
    """
    return hmac.new(key, data, hashlib.sha512).digest()


def hkdf_extract(salt, ikm):
    if len(salt) == 0:
        salt = bytes(32)
    prk = hmac_sha256(salt, ikm)
    return prk


def hkdf_expand(prk, info, length):
    okm = b""
    iter_value = b""
    for i in range(ceil(length / 32)):
        iter_value = hmac_sha256(prk, iter_value + info + bytes([i+1]))
        okm += iter_value
    return okm[:length]


def hkdf(salt, ikm, info, length):
    prk = hkdf_extract(salt, ikm)
    key = hkdf_expand(prk, info, length)
    return key

if __name__ == '__main__':
    salt = bytes.fromhex("8e7c57929d750e4b892bb1421775f393" \
                         "ddf96b3ddf630624b5d73232c0f88ce6")
    # The key and the arbitrary info bytes are of course badly chosen
    print(hkdf(salt, b"keykeykeykey", b"info", 20))
