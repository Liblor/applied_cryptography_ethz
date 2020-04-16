#!/usr/bin/env python3
#
# Applied Cryptography 2020 @ ETHZ
# Loris Reiff
#
from lab_07_sha1_mod import sha1_mod
from lab_07_sha1 import sha1
import hashlib
import struct
from os import urandom


def verify_implementation(data):
    output = sha1(data)
    hash = hashlib.sha1(data)
    hashlib_output = hash.digest()
    return output == hashlib_output


# XXX: this is not a true MAC
def sha_one_mac(key, data):
    return sha1(key + data)


def sha_msg_mac(key, data):
    return data + sha_one_mac(key, data)


def hashlib_sha_one_mac(key, data):
    h = hashlib.sha1(key + data)
    return h.digest()


def hashlib_sha_msg_mac(key, data):
    return data + hashlib_sha_one_mac(key, data)


def auth_msg_verify(key, auth_msg):
    sha1_len = 20
    msg = auth_msg[:-sha1_len]
    mac = auth_msg[-sha1_len:]
    return hashlib_sha_one_mac(key, msg) == mac


def module_1_sha1_mac():
    # Test sha implementation
    assert(verify_implementation(b"hello"))

    # Test dummy MAC
    KEY_HEX = "80ba9bdd231e1c2bad4ceee321837490" \
              "d325ea3e5f9467224354951f5d92b37a"
    KEY = bytes.fromhex(KEY_HEX)
    LYRIC_STRING = "She whispered 'wait for the trumpet's call', " \
                   "it's not exactly love, it's t'adore"
    LYRIC_BYTES = LYRIC_STRING.encode()
    LYRIC_MAC_HEX = "d3bc740d402c2f3e798205ed95dd69494e2e9afc"
    LYRIC_MAC_BYTES = bytes.fromhex(LYRIC_MAC_HEX)
    assert(sha_one_mac(KEY, LYRIC_BYTES) == LYRIC_MAC_BYTES)


################ MODULE 2 ################
def sha_one_padding(msg, pad_len):
    padding_zero_len = -(pad_len + 1 + 64) % 512
    padded_msg = msg + bytes([0b10000000]) + b'\x00'*(padding_zero_len//8) \
                     + pad_len.to_bytes(8, byteorder='big')
    return padded_msg


def length_extension(auth_msg, ext, key_len=32):
    # SHA1 is 20 bytes
    msg = auth_msg[:-20]
    mac_tag = auth_msg[-20:]
    msg_len = len(msg)

    keyed_msg_bit_len = 8 * (msg_len + key_len)
    padding_msg = sha_one_padding(msg, keyed_msg_bit_len)
    forged_msg = padding_msg + ext

    init = []
    for i in range(0, 20, 4):
        init_bytes = mac_tag[i:i+4]
        init_int = int.from_bytes(init_bytes, byteorder="big")
        init.append(init_int)

    padding_len = len(forged_msg) + key_len
    forged_mac = sha1_mod(ext, init[0], init[1], init[2], init[3],
                          init[4], padding_len)
    return forged_msg + forged_mac


def module_2_length_extension_attack():
    KEY_HEX = "80ba9bdd231e1c2bad4ceee321837490" \
              "d325ea3e5f9467224354951f5d92b37a"
    USER_STRING = "username=ILoveToBakePie"
    ADMIN_STRING = ";user_data=admin;"
    KEY = bytes.fromhex(KEY_HEX)
    USER_BYTES = USER_STRING.encode()
    ADMIN_BYTES = ADMIN_STRING.encode()

    auth_user_msg = hashlib_sha_msg_mac(KEY, USER_BYTES)
    assert(auth_msg_verify(KEY, auth_user_msg))

    forged_msg = length_extension(auth_user_msg, ADMIN_BYTES)
    assert(auth_msg_verify(KEY, forged_msg))
    print("length extension attack successful!")


if __name__ == '__main__':
    module_1_sha1_mac()
    module_2_length_extension_attack()
