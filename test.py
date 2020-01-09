import os
import string
import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

SYM_ALGO = algorithms.AES
SYM_MODE = modes.CBC
ASYM_ALGO = rsa

def sym_cypher(key_length, block_length, message):
    # print("Generating keys...")
    key = os.urandom(key_length)
    iv = os.urandom(block_length)

    cipher = Cipher(SYM_ALGO(key), SYM_MODE(iv), backend=default_backend())

    encryptor = cipher.encryptor()
    c_message = encryptor.update(message) + encryptor.finalize()
    return c_message, key

def asym_cypher(key_size, message):
    key = ASYM_ALGO.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    c_message = key.public_key().encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return c_message


def generate_message(length):
    allchar = string.ascii_letters + "." + string.digits
    message = "".join(random.choice(allchar) for x in range(length))
    b_message = message.encode("ascii")
    return b_message


def cyphered_length(sym_key_length, sym_block_length, asym_key_length, message_len):
    message = generate_message(message_len)

    sym_message, key = sym_cypher(sym_key_length, sym_block_length, message)
    print("Sym message : %d" % len(sym_message))
    print("Sym message + key : %d" % len(sym_message+key))

    full_message = asym_cypher(asym_key_length, sym_message+key)

    return len(full_message)

if __name__ == "__main__":
    for l in range(16, 257, 16):
        print("%d -> %d" % (l, cyphered_length(32, 16, 2048, l)))


