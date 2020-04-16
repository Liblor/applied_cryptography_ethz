#!/usr/bin/env python3
#
# Applied Cryptography 2020 @ ETHZ
# Loris Reiff
#
import hashlib
import os


def signal_fp_gen(version, pub_key, identity, num_iterations):
    # according to the lab text this has to be b'0', but
    # shouldn't this be b'\x00'?
    fprint = b"0" + version + pub_key + identity
    sha256 = hashlib.sha512(fprint)
    iter_value = sha256.digest()
    for i in range(num_iterations):
        iter_hash = hashlib.sha256(iter_value + pub_key)
        iter_value = iter_hash.digest()
    return iter_value


def signal_trunc_fp(fingerprint, num_chunks=6):
    trunc_fp = []
    for i in range(num_chunks):
        chunk = fingerprint[5*i:5*(i+1)]
        val = int.from_bytes(chunk, byteorder="big")
        val = val % 100000
        trunc_fp.append(f"{val:05}")
    return " ".join(trunc_fp)


def signal_display_gen(version, alice_key, alice_id, bob_key, bob_id,
                       num_iterations):
    alice_fp = signal_fp_gen(version, alice_key, alice_id, num_iterations)
    alice_human_fp = signal_trunc_fp(alice_fp)
    bob_fp = signal_fp_gen(version, bob_key, bob_id, num_iterations)
    bob_human_fp = signal_trunc_fp(bob_fp)
    return " ".join([alice_human_fp, bob_human_fp])


def collision(version, alice_key, alice_id, bob_key, bob_id, num_iterations):
    pub_key_size = len(alice_key)

    alice_fp = signal_fp_gen(version, alice_key, alice_id, num_iterations)
    alice_human = signal_trunc_fp(alice_fp, 1)
    bob_fp = signal_fp_gen(version, bob_key, bob_id, num_iterations)
    bob_human = signal_trunc_fp(bob_fp, 1)
    collision_key = os.urandom(pub_key_size)
    collision_fp = signal_fp_gen(version, collision_key, alice_id,
                                 num_iterations)
    collision_human = signal_trunc_fp(collision_fp, 1)

    i = 0
    while (collision_human != alice_human):
        if (i % 1000 == 0):
            print("Tries:", i)
        collision_key = os.urandom(pub_key_size)
        collision_fp = signal_fp_gen(version, collision_key, alice_id,
                                     num_iterations)
        collision_human = signal_trunc_fp(collision_fp, 1)
        i = i + 1
    print("COLLISION FOUND!")


if __name__ == '__main__':
    ALICE_IDENTITY = "Alice"
    ALICE_PUB_KEY = "a7904d681db3e90638ae1c03f3597af6"\
                    "f65c9d23428892736e2d18b8f7d62dc2"\
                    "bd17c2a155ae8e037ed222a1be9415d7"
    BOB_IDENTITY = "Bob"
    BOB_PUB_KEY = "83aaab0e9de3c585584a77962d8d735d"\
                  "d6a030665964f2385f21177a723ef37b"\
                  "06b76008dddecaac438ad0c87f2c48a7"
    collision(b"0", bytes.fromhex(ALICE_PUB_KEY), ALICE_IDENTITY.encode(),
              bytes.fromhex(BOB_PUB_KEY), BOB_IDENTITY.encode(), 5200)
