#!/usr/bin/env python3
#
# Applied Cryptography 2020 @ ETHZ
# Loris Reiff
#
import hashlib
from Crypto.Hash import SHA, HMAC, SHA256
from Crypto.Random import get_random_bytes


# Answer: No, MD5 is not a secure password hashing scheme.
# It can be calculated super fast (also there are collsion attacks)
def pw_hash_one(password):
    hash = hashlib.md5(password)
    return hash.digest()


# Answer: While a salt of 10 bytes should be enough to avoid random salt
# collisions (-> birthday paradox). HMAC_SHA can be computed too efficiently
# and should be avoided as a password hash.
def pw_hash_two(password):
    salt = get_random_bytes(10)
    hash = HMAC.new(password, salt, SHA)
    return (salt, hash.digest())


def pw_hash_two_verify(password, salt):
    hash = HMAC.new(password, salt, SHA)
    return hash.digest()


# Answer: No, this scheme is not secure against a pre-computed
# directory attack
def pw_hash_three(password):
    hash = HMAC.new("".encode(), password, SHA256)
    return hash.digest()


# Answer: When the attack doesn't have access to the key, he/she cannot simply
# perform a precomputation attack however if he/she is in possession of the
# key, the attacker can easily precompute the passwords
def pw_hash_four(password, key):
    hash = HMAC.new(key, password, SHA256)
    return hash.digest()


# Answer:
# n - iteration count -> CPU/memory cost parameter
# r - blocksize parameter (seq. mem reads)
# p - parallelization factor
def pw_hash_five(password):
    salt = get_random_bytes(32)
    return hashlib.scrypt(password, salt=salt, n=2**10, r=32, p=2)


def pw_hash_five_verify(password, salt):
    return hashlib.scrypt(password, salt=salt, n=2**10, r=32, p=2)


def fb_pw_hash(password, key, salt):
    h1 = pw_hash_one(password)
    hash = HMAC.new(h1, salt, SHA)
    h2 = hash.digest()
    hash = HMAC.new(key, h2, SHA256)
    h3 = hash.digest()
    h4 = hashlib.scrypt(h3, salt=salt, n=2**10, r=32, p=2)
    h5 = pw_hash_three(h4)
    return h5


def fb_pw_onion(password, key):
    salt = get_random_bytes(20)
    h = fb_pw_hash(password, key, salt)
    return (salt, h)


def fb_pw_onion_verify(password, password_hash, key, salt):
    h = fb_pw_hash(password, key, salt)
    return h == password_hash


if __name__ == '__main__':
    test_pw = b"test_pw"
    test_salt = bytes.fromhex("5092f463f873a9e0e16d64979c11bad210835f60")
    hashed_pw = bytes.fromhex("497fca6772ae14901915ea11de6fa90b"
                              "046a28106b99ed5061ed24042cd33936")
    test_key = bytes.fromhex("49e8ba58aadf432cc2ce0b35ffa83fab476d9db7")
    assert(fb_pw_onion_verify(test_pw, hashed_pw, test_key, test_salt))
