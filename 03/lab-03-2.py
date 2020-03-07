#!/usr/bin/env python3
#
# Applied Cryptography 2020 @ ETHZ
# Loris Reiff
#
from Crypto.Cipher import AES

CONST_KEY  = bytes.fromhex("dd59418c90d52a811da90535dc2654fc")
CIPHERTEXT = bytes.fromhex("fb5e756b677cca8e4fbc36ca155e6703891157cba968755c44"\
                           "f2a612cf8800c5c0779a414595def312e114a733394191")

def ecb_encryption(text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(text)

def ecb_decryption(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def padded_oracle(prepend_pad, append_pad, ciphertext, key):
    plaintext = ecb_decryption(ciphertext, key)
    padded_plaintext = prepend_pad + plaintext + append_pad
    ciphertext = ecb_encryption(padded_plaintext, key)
    return ciphertext

def create_dict(pre):
    p = bytearray(pre + b'\x00')
    d = dict()
    for i in range(256):
        p[-1] = i
        c = padded_oracle(bytes(p), b'', b'', CONST_KEY)
        d[c] = bytes([i])
    return d

def get_nth_block(data, n, block_size):
    return data[n*block_size:(n+1)*block_size]

def padding_for_ith_byte(i, block_size):
    bs = block_size
    s = bs - 1
    return b'\x00'*(s - i%bs)

def recover_plaintext(ciphertext, key, block_size=16):
    recovered = b'\x00'*(block_size - 1)
    for i in range(len(ciphertext)):
        # recover i-th byte
        block_nr = i // block_size
        d = create_dict(recovered[-(block_size-1):])

        prepend = padding_for_ith_byte(i, block_size)
        c = padded_oracle(prepend, ((i+1)%block_size) * b'\x00', ciphertext, key)

        block_to_recover = get_nth_block(c, block_nr, block_size)
        recovered += d[block_to_recover]

        # print status
        print(recovered.decode())
    return recovered[block_size-1:]

if __name__ == '__main__':
    print(recover_plaintext(CIPHERTEXT, CONST_KEY).decode())
