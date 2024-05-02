from typing import Tuple
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac


def kdf_rk(rk, dh_out):
    hkdf = HKDF(
        length=64,
        salt=rk,
        algorithm=hashes.SHA256(),
        info=b"info"
        )
    key = hkdf.derive(dh_out)


    root_key = key[:32]
    chain_key = key[32:]
    return root_key, chain_key




def symmetric_ratchet(chain_key: bytes) -> Tuple[bytes, bytes]:
    """Symmetric key ratchet
    https://signal.org/docs/specifications/doubleratchet/#symmetric-key-ratchet
    https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms
    https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#hkdf

    Args:
        constant: Some constant used in the KDF
        chain_key: The chain key that is used in the KDF

    Returns:
        Tuple[bytes, bytes]: new chain_key, message_key
    """
    h1 = hmac.HMAC(chain_key, hashes.SHA256())
    h1.update(b'\x01')
    message_key = h1.finalize()

    h2 = hmac.HMAC(chain_key, hashes.SHA256())
    h2.update(b'\x02')
    next_chain_key = h2.finalize()

    return message_key, next_chain_key


def encrypt_message(message: bytes, message_key: bytes) -> bytes:
    """Encrypt the given message using the given message key
        https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
    """
    iv = b"0123456789123456"
    cipher = Cipher(algorithms.AES(message_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(message) + encryptor.finalize()
    return cipher_text

def decrypt_message(cipher_text: bytes, message_key: bytes) -> bytes:
    """Decrypt the given message using the given message key
        https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
    """
    iv = b"0123456789123456"
    cipher = Cipher(algorithms.AES(message_key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(cipher_text) + decryptor.finalize()
    return plain_text


if __name__ == "__main__":
    constant = b"abcdef00"
    chain_key = b"ffaabcc"
    print("initial constant is : "+str(constant))
    print("initial chain_key is : "+str(chain_key))
    root_key, chain_key = kdf_rk(constant, chain_key)
    print("initial root_key is : "+str(root_key))
    print("initial chain_key after kdf_rk is : "+str(chain_key))

    message_1 = b"hallo alice"
    cipher_text = encrypt_message(message_1, root_key)
    print("bob encrypts: " + str(message_1))
    print("bob's cipher_text is : "+str(cipher_text))
    plain_text = decrypt_message(cipher_text, root_key)
    print("alice decrypts: "+str(plain_text))

    message_key, chain_key = symmetric_ratchet(chain_key)

    message_2 = b"I am good."
    cipher_text = encrypt_message(message_2, message_key)
    print("alice encrypts: " + str(message_2))
    print("alice's cipher_text is : "+str(cipher_text))
    plain_text = decrypt_message(cipher_text, message_key)
    print("bob decrypts: "+str(plain_text))

    message_key, chain_key = symmetric_ratchet(chain_key)

    message_3 = b"I am also fine, what are you currently doing?"
    cipher_text = encrypt_message(message_3, message_key)
    print("bob encrypts: " + str(message_3))
    print("bob's cipher_text is : "+str(cipher_text))
    plain_text = decrypt_message(cipher_text, message_key)
    print("alice decrypts: "+str(plain_text))

    message_key, chain_key = symmetric_ratchet(chain_key)

    message_4 = b"I am working on the NetSec homework."
    cipher_text = encrypt_message(message_4, message_key)
    print("alice encrypts: " + str(message_4))
    print("alice's cipher_text is : "+str(cipher_text))
    plain_text = decrypt_message(cipher_text, message_key)
    print("bob decrypts: "+str(plain_text))

    message_key, chain_key = symmetric_ratchet(chain_key)

    message_5 = b"Then goood luck with it!"
    cipher_text = encrypt_message(message_5, message_key)
    print("bob encrypts: " + str(message_5))
    print("bob's cipher_text is : "+str(cipher_text))
    plain_text = decrypt_message(cipher_text, message_key)
    print("alice decrypts: "+str(plain_text))

    message_key, chain_key = symmetric_ratchet(chain_key)

