from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto.Random import get_random_bytes

master_secret = "The Living End"
HEX_CIPHERTEXT = "2ff41807f83f9458c0b70ce49858945c"\
"959ab118c831a88d196f30da504d3215"\
"2669d35b0c1a528bc14ae8ef75c592c5"\
"74a3bd2480aa2335ea6495140bc66ee6"\
"b804a4630ffb820764d24c243535d38b"\
"fefa0960dc4fa63509c23a03f10f67d1"\
"9e009725ddfd88d6ef93ac283f8900c2"\
"933ea6cfceb0cd2473d77b835669c928"\
"fc8b026d0f685cabb1627cfc96716b7f"
KEY_LENGTH = 16
BLOCK_LENGTH = 16

# ERROR MESSAGES

class PaddingError(Exception):
    # We raise a padding error if padding error is wrong
    pass

class LengthError(Exception):
    # We raise a length error if the padding byte is greater
    # than the BLOCK_LENGTH
    pass

class MacLengthError(Exception):
    # We raise a mac length error if the output mac
    # is not a multiple of the BLOCK_LENGTH
    pass

class MACFailure(Exception):
    # We raise a MAC failure error if the locally computed
    # MAC does not match the MAC that has been recieved
    pass

def create_single_char_string(char, length):
    char_set = []
    for i in range(length):
        char_set.append(chr(ord(char)))
    string = "".join(char_set)
    return string

def kdf(ms):
    kdf = SHA256.new()
    kdf.update(ms)
    key_material = kdf.digest()
    enc_key = key_material[:KEY_LENGTH]
    mac_key = key_material[KEY_LENGTH:]
    return enc_key, mac_key

def add_padding(plaintext):
    # Pad plaintext to multiples of BLOCK_LENGTH
    padding_length = BLOCK_LENGTH - (len(plaintext) % BLOCK_LENGTH)
    if padding_length == 0:
        padding_length = BLOCK_LENGTH
    padding = create_single_char_string(chr(padding_length-1), padding_length)
    padded_plaintext = plaintext + padding.encode()
    return padded_plaintext

def remove_padding(padded_plaintext):
    # Remove padding
    pptext_length = len(padded_plaintext)
    padding_length = padded_plaintext[pptext_length-1] + 1
    if padding_length > BLOCK_LENGTH:
        raise LengthError()
    for i in range(padding_length):
        if padded_plaintext[pptext_length - i-1] != (padding_length-1):
            raise PaddingError()
    plaintext = padded_plaintext[:pptext_length - padding_length]
    return plaintext

def add_mac(message, key):
    hash = HMAC.new(key, digestmod=SHA256)
    hash.update(message)
    mac = hash.digest()
    if ((len(mac) % BLOCK_LENGTH) != 0):
        raise MacLengthError()
    auth_message = mac + message
    return auth_message

def check_and_remove_mac(message, key):
    hash = HMAC.new(key, digestmod=SHA256)
    recd_mac = message[:SHA256.digest_size]
    plaintext = message[SHA256.digest_size:]
    hash.update(plaintext)
    comp_mac = hash.digest()
    if ((len(comp_mac) % BLOCK_LENGTH) != 0):
        raise MacLengthError()
    if recd_mac != comp_mac:
        raise MACFailure()
    return plaintext

def encrypt(plaintext, key):
    # Encrypt plaintext under "key" using AES-128 in CBC
    # with random IVs
    iv = get_random_bytes(BLOCK_LENGTH)
    cipher = AES.new(key, mode=AES.MODE_CBC, IV=iv)
    ciphertext = cipher.encrypt(plaintext)
    return iv+ciphertext

def decrypt(ciphertext, key):
    # Decrypt the ciphertext under key in AES-CBC mode
    iv = ciphertext[:BLOCK_LENGTH]
    ciphertext = ciphertext[BLOCK_LENGTH:]
    cipher = AES.new(key, mode=AES.MODE_CBC, IV=iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def mee_encrypt(plaintext, seed):
    enc_key, mac_key = kdf(seed)
    authenticated = add_mac(plaintext, mac_key)
    encoded = add_padding(authenticated)
    return encrypt(encoded, enc_key)

def mee_decrypt(ciphertext, seed):
    enc_key, mac_key = kdf(seed)
    encoded = decrypt(ciphertext, enc_key)
    authenticated = remove_padding(encoded)
    plaintext = check_and_remove_mac(authenticated, mac_key)
    return plaintext

def decryption_error(ciphertext):
    master_secret = "The Living End"
    mee_decrypt(ciphertext, master_secret.encode())

def padding_oracle(ciphertext):
    try:
        decryption_error(ciphertext)
    except MACFailure:
        return True
    except LengthError:
        return False
    except PaddingError:
        return False
    return True

def xor_value_at_pos(bytes_string, pos, value):
    xor_byte = bytes_string[pos] ^ value
    xor_bytes = []
    for i in range(pos):
        xor_bytes.append(bytes_string[i])
    xor_bytes.append(xor_byte)
    for i in range(len(bytes_string) - pos - 1):
        xor_bytes.append(bytes_string[pos + 1 + i])
    xor_bytes = bytes(xor_bytes)
    return xor_bytes

def attack_mee_byte(ciphertext):
    b = ciphertext[:-BLOCK_LENGTH]      # Otherwise we get 0x15 which is padding
    attack_pos = len(b) - BLOCK_LENGTH - 1
    for i in range(256):
        mod = xor_value_at_pos(b, attack_pos, i)
        if padding_oracle(mod):
            # make sure it doesn't end randomly with 0x0101
            if padding_oracle(xor_value_at_pos(mod, attack_pos-1, 0x11)):
                return chr(i)

def xor_end(c_block, ptxt, offset):
    assert(len(c_block) >= len(ptxt))
    out = c_block
    for i in range(len(ptxt)):
        out = xor_value_at_pos(out, len(out)-BLOCK_LENGTH-(i+1), (ord(ptxt[i]) ^ offset))
    return out

def attack_mee_block(ciphertext):
    out = attack_mee_byte(ciphertext)
    b = ciphertext[:-BLOCK_LENGTH]      # Otherwise we get 0x15 which is padding
    attack_pos = len(b) - BLOCK_LENGTH - 1
    for i in range(1, 16):
        attack_pos -= 1
        working_b = xor_end(b, out, i)
        for j in range(256):
            if padding_oracle(xor_value_at_pos(working_b, attack_pos, j)):
                break
        out += chr(j ^ i)
    return out[::-1]

def attack_mee_ciphertext(ciphertext):
    out = ""
    # we have to remove 4 blocks for the mac
    plaintext_num_blocks = len(ciphertext) // BLOCK_LENGTH - 4
    for i in range(plaintext_num_blocks-1, -1, -1):
        out += attack_mee_block(ciphertext[:len(ciphertext)-i*BLOCK_LENGTH])
    return out

if __name__ == '__main__':
    ciphertext = bytes.fromhex(HEX_CIPHERTEXT)
    print(attack_mee_ciphertext(ciphertext))
