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


c1 = "542055804aac960f97963f3a649e48335df8631c4a7a6b4500"\
     "a5c7ec8573ea89970b296b50b491ca0d0ae14e6e0bd7f9d06a"\
     "5db3e405bd53c1960bcd810b278b4acf12a1205c59263d"
c1 = bytes.fromhex(c1)
c2 = "2f7442c908accf0fd1d76b7f75ca1f7f0bf839455e3b304550"\
     "e19ea3c57fffcfd047766b0af28299545fbf0a7c4a81bdc72c"\
     "1ce1aa05ff1a95d8578bca427fcc5c814ff57c150e6124"
c2 = bytes.fromhex(c2)

m1 = bytearray(len(c1))
xr = xor(c1, c2)

for i in range(1, len(c1), 2):
    m1[i] = xr[i] ^ ord(" ")

print(m1)
key = xor(c1, b"It is a tale told by an idiot, full of sound and fury signifying nothing.")
print(xor(c2, key))
