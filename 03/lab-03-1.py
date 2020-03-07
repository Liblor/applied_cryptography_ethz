#!/usr/bin/env python3
#
# Applied Cryptography 2020 @ ETHZ
# Loris Reiff
#
from collections import defaultdict

def max_block_repetitions(data, length):
    assert(len(data) % length == 0)
    maxi = 0
    d = defaultdict(lambda : 0)
    for i in range(len(data) // length):
        b = data[i*length:(i+1)*length]
        d[b] += 1
        maxi = max(maxi, d[b])
    return maxi

def is_ebc(hexstring):
    l = max_block_repetitions(hexstring, 32)
    return l >= 2


if __name__ == '__main__':
    ebc = []
    with open("8.txt", "r") as f:
        for i, line in enumerate(f):
            if is_ebc(line[:-1]):
                ebc.append(i)
    print(*ebc, sep=', ')

