#!/usr/bin/env python3
#
# Applied Cryptography 2020 @ ETHZ
# Loris Reiff
#
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter
KEY_SIZE = 16
BLOCK_SIZE = 16

CONST_PLAINTEXT = "Hey, I just met you and this is crazy but here's my number so call me maybe"

def generate_aes_key(key_length):
    """
    Use get_random_bytes to generate a key of the
    appropriate length
    """
    key = get_random_bytes(key_length)
    return key

def create_single_char_string(char, length):
    char_set = []
    for i in range(length):
        char_set.append(chr(ord(char)))
    string = "".join(char_set)
    return string

def add_padding(plaintext, block_length):
    """
    Adds padding to the plaintext, making the length of the
    padding + plaintext a multiple of the block length (16 bytes)
    Note that if the length of the plaintext is already a multiple
    of the block-length, a full block of padding is added
    """
    padding_len = block_length - len(plaintext) % block_length
    if (padding_len == 0):
        padding_len += block_length
    padding = bytes([padding_len-1] * padding_len)
    padded_plaintext = plaintext + padding
    return padded_plaintext

def remove_padding(padded_plaintext, block_length):
    """
    Removes padding from the padded_plaintext
    """
    padding_len = padded_plaintext[-1] + 1
    padding = padded_plaintext[-padding_len:]
    # we should check that the padding is correct
    # but this facilitates padding oracle attacks...
    # correct_padding = all(map(lambda x: x == padded_plaintext[-1], padded_plaintext))
    plaintext = padded_plaintext[:-padding_len]
    return plaintext

def aes_ecb_encryption(plaintext, key, block_length):
    """
    Pads the plaintext using add_padding, and then
    initialises a new AES cipher object in ECB mode.
    Encrypt the plaintext under the given key, and
    return the ciphertext
    """
    padded_ptxt = add_padding(plaintext, block_length)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(padded_ptxt)
    return ciphertext

def aes_ecb_decryption(ciphertext, key, block_length):
    """
    Decrypt the ciphertext under the given key, and
    remove the padding from the padded_plaintext
    using remove_padding. Return the plaintext.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = remove_padding(padded_plaintext, block_length)
    return plaintext

def aes_cbc_encryption(plaintext, key, block_length):
    """
    Generate an IV, then pad the plaintext using
    add_padding. Initialise a new AES cipher object
    in CBC mode. Encrypt the plaintext using the key
    and the IV, and concatenate the ciphertext and the
    iv. Return the ciphertext.
    """
    iv = get_random_bytes(block_length)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = add_padding(plaintext, block_length)
    ciphertext = iv + cipher.encrypt(padded_plaintext)
    return ciphertext

def aes_cbc_decryption(ciphertext, key, block_length):
    """
    Recover the IV from the ciphertext, then inialise
    a new AES cipher object in CBC mode. Decrypt the
    ciphertext using the key and the IV, and remove
    the padding. Return the plaintext.
    """
    iv = ciphertext[:block_length]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext[block_length:])
    plaintext = remove_padding(padded_plaintext, block_length)
    return plaintext

def aes_ctr_encryption(plaintext, key, block_length, ctr):
    """
    Pad the plaintext using add_padding. Initialise a new
    AES cipher object in CTR mode using the given ctr.
    Encrypt the padded plaintext using the key, and return
    the ciphertext.
    """
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    padded_plaintext = add_padding(plaintext, block_length)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def aes_ctr_decryption(ciphertext, key, block_length, ctr):
    """
    Inialise a new AES cipher object in CTR mode. Decrypt the
    ciphertext using the key, and remove the padding.
    Return the plaintext.
    """
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    padded_plaintext = cipher.encrypt(ciphertext)
    plaintext = remove_padding(padded_plaintext, block_length)
    return plaintext

if __name__ == '__main__':
    key = generate_aes_key(KEY_SIZE)
    ptxt = CONST_PLAINTEXT.encode()
    ecb_c = aes_ecb_encryption(ptxt, key, BLOCK_SIZE)
    assert(ecb_c != ptxt)
    ecb_p = aes_ecb_decryption(ecb_c, key, BLOCK_SIZE)
    assert(ecb_p == ptxt)

    cbc_c = aes_cbc_encryption(ptxt, key, BLOCK_SIZE)
    assert(cbc_c != ptxt)
    cbc_p = aes_cbc_decryption(cbc_c, key, BLOCK_SIZE)
    assert(cbc_p == ptxt)

    ctr = Counter.new(128)
    ctr_d = Counter.new(128)
    ctr_c = aes_ctr_encryption(ptxt, key, BLOCK_SIZE, ctr)
    assert(ctr_c != ptxt)
    ctr_p = aes_ctr_decryption(ctr_c, key, BLOCK_SIZE, ctr_d)
    assert(ctr_p == ptxt)
