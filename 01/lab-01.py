#!/usr/bin/env python3
#
# Applied Cryptography 2020 @ ETHZ
# Loris Reiff
#
from itertools import cycle
from base64 import b64encode
from binascii import unhexlify
import string

def xor(data, key):
    out = bytearray()
    for (b, k) in zip(data, cycle(key)):
        out.append(b ^ k)
    return out


def format_conversion():
    print("Format Conversion")
    karma_police = b"Karma police, arrest this man, he talks in maths"

    #1
    print("1.")
    print(karma_police.hex())
    print()

    c = xor(karma_police, b'\x01')
    base_c = b64encode(c)
    print(base_c.decode())


def single_byte_xor_cipher():
    c = b"210e09060b0b1e4b4714080a02080902470b0213470a0247081213470801470a1e4704060002"
    c_b = unhexlify(c)
    key = 0
    for i in range(256):
        plaintext = xor(c_b, [i])
        is_printable = all(chr(ch) in string.printable for ch in plaintext)
        if is_printable and plaintext.count(b" ") > 4:
            print(i, plaintext.decode())

format_conversion()
single_byte_xor_cipher()
