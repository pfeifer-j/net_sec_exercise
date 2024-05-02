from typing import Tuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac


def kdf_rk(rk, dh_out):
    hkdf = HKDF(length=64, salt=rk, algorithm=hashes.SHA256(), info=b"info")
    key = hkdf.derive(dh_out)

    root_key = key[:32]
    chain_key = key[32:]

    return root_key, chain_key


def symmetric_ratchet(chain_key: bytes) -> Tuple[bytes, bytes]:
    """Symmetric key ratchet

    Args:
        chain_key: The chain key used in the KDF

    Returns:
        Tuple[bytes, bytes]: new chain_key, message_key
    """
    h1 = hmac.HMAC(chain_key, hashes.SHA256())
    h1.update(b"\x01")
    message_key = h1.finalize()

    h2 = hmac.HMAC(chain_key, hashes.SHA256())
    h2.update(b"\x02")
    next_chain_key = h2.finalize()

    return message_key, next_chain_key


def encrypt_message(message: bytes, message_key: bytes) -> bytes:
    """Encrypts the message using the message key"""
    iv = b"0123456789123456"
    cipher = Cipher(algorithms.AES(message_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(message) + encryptor.finalize()

    return cipher_text


def decrypt_message(cipher_text: bytes, message_key: bytes) -> bytes:
    """Decrypts the message using the message key"""
    iv = b"0123456789123456"
    cipher = Cipher(algorithms.AES(message_key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(cipher_text) + decryptor.finalize()

    return plain_text


if __name__ == "__main__":
    constant = b"abcdef00"
    chain_key = b"ffaabcc"

    print("Initial constant: ", constant)
    print("Initial chain key: ", chain_key)
    print()

    root_key, chain_key = kdf_rk(constant, chain_key)
    print("Root key after KDF: ", root_key)
    print("Chain key after KDF: ", chain_key)
    print()

    message_1 = b"Hello Alice!"
    cipher_text = encrypt_message(message_1, root_key)
    print("Bob encrypts: ", message_1)
    print("Bob's cipher text: ", cipher_text)
    plain_text = decrypt_message(cipher_text, root_key)
    print("Alice decrypts: ", plain_text)
    print()

    message_key, chain_key = symmetric_ratchet(chain_key)

    message_2 = b"I'm good, thank you."
    cipher_text = encrypt_message(message_2, message_key)
    print("Alice encrypts: ", message_2)
    print("Alice's cipher text: ", cipher_text)
    plain_text = decrypt_message(cipher_text, message_key)
    print("Bob decrypts: ", plain_text)
    print()

    message_key, chain_key = symmetric_ratchet(chain_key)

    message_3 = b"I'm also fine, what are you up to?"
    cipher_text = encrypt_message(message_3, message_key)
    print("Bob encrypts: ", message_3)
    print("Bob's cipher text: ", cipher_text)
    plain_text = decrypt_message(cipher_text, message_key)
    print("Alice decrypts: ", plain_text)
    print()

    message_key, chain_key = symmetric_ratchet(chain_key)

    message_4 = b"I'm working on the NetSec homework."
    cipher_text = encrypt_message(message_4, message_key)
    print("Alice encrypts: ", message_4)
    print("Alice's cipher text: ", cipher_text)
    plain_text = decrypt_message(cipher_text, message_key)
    print("Bob decrypts: ", plain_text)
    print()

    message_key, chain_key = symmetric_ratchet(chain_key)

    message_5 = b"Then good luck with it!"
    cipher_text = encrypt_message(message_5, message_key)
    print("Bob encrypts: ", message_5)
    print("Bob's cipher text: ", cipher_text)
    plain_text = decrypt_message(cipher_text, message_key)
    print("Alice decrypts: ", plain_text)
    print()

    message_key, chain_key = symmetric_ratchet(chain_key)
