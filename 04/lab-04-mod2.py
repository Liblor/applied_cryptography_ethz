#!/usr/bin/env python3
#
# Applied Cryptography 2020 @ ETHZ
# Loris Reiff
#
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

KEY_SIZE = 16
BLOCK_SIZE = 16

def generate_aes_key(key_length):
    key = get_random_bytes(key_length)
    return key

def create_single_char_string(char, length):
    char_set = []
    for i in range(length):
        char_set.append(chr(ord(char)))
    string = "".join(char_set)
    return string

def aes_cbc_encryption(plaintext, key, block_length):
    plaintext = plaintext.encode()
    iv = get_random_bytes(block_length)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = add_padding(plaintext, block_length)
    ciphertext = iv + cipher.encrypt(padded_plaintext)
    return ciphertext

def aes_cbc_decryption(ciphertext, key, block_length):
    iv = ciphertext[:block_length]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext[block_length:])
    plaintext = remove_padding(padded_plaintext, block_length)
    #return plaintext.decode()
    return plaintext

def add_padding(plaintext, block_length):
    padding_len = block_length - len(plaintext) % block_length
    if (padding_len == 0):
        padding_len += block_length
    padding = bytes([padding_len-1] * padding_len)
    padded_plaintext = plaintext + padding
    return padded_plaintext

def remove_padding(padded_plaintext, block_length):
    padding_len = padded_plaintext[-1] + 1
    padding = padded_plaintext[-padding_len:]
    # we should check that the padding is correct
    # but this facilitates padding oracle attacks...
    # correct_padding = all(map(lambda x: x == padded_plaintext[-1], padded_plaintext))
    plaintext = padded_plaintext[:-padding_len]
    return plaintext

def prepend_and_append(prepend_string, string, append_string):
    plaintext = prepend_string + string + append_string
    plaintext = remove_admin(plaintext)
    return plaintext

def remove_admin(string):
    string = string.replace(";admin;", "")
    return string

def concatenate_and_encrypt(prepend_string, mid_string, append_string, aes_key, block_length):
    plaintext = prepend_and_append(prepend_string, mid_string, append_string)
    ciphertext = aes_cbc_encryption(plaintext, aes_key, block_length)
    return ciphertext

def encryption_oracle(plaintext, key, block_length):
    prepend_string = "username=ILoveToBakePie;userdata="
    append_string = ";username=ILoveToBakeCakes;userdata=Mod"
    ciphertext = concatenate_and_encrypt(prepend_string, plaintext, append_string, key, block_length)
    return ciphertext

def decryption_oracle(ciphertext, key, block_length):
    plaintext = aes_cbc_decryption(ciphertext, key, block_length)
    return plaintext

def is_admin(ciphertext, key, block_length):
    plaintext = decryption_oracle(ciphertext, key, block_length)
    print(plaintext)
    result = str(plaintext).find(';admin;')
    if result == -1:
        answer = "Not Admin"
    else:
        answer = "Admin"
    return answer

def make_admin(ciphertext, block_length, pos_one):
    ctxt = bytearray(ciphertext)
    idx = pos_one // 8
    flip_bit_idx =  pos_one % 8
    ctxt[idx] ^= 1 << flip_bit_idx
    return bytes(ctxt)


if __name__ == '__main__':
    # Simple injection doesn't work
    aes_key = generate_aes_key(KEY_SIZE)
    ciphertext_test = encryption_oracle(";admin;", aes_key, BLOCK_SIZE)
    print(ciphertext_test)
    test_answer = is_admin(ciphertext_test, aes_key, BLOCK_SIZE)
    print(test_answer)

    # Attack
    ciphertext_test = encryption_oracle(32*"A" + ";admin:" + 16*"B", aes_key, BLOCK_SIZE)
    ciphertext_test = make_admin(ciphertext_test, BLOCK_SIZE, 71*8)
    test_answer = is_admin(ciphertext_test, aes_key, BLOCK_SIZE)
    print(test_answer)
