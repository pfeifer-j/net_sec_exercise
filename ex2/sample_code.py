from typing import Tuple

def symmetric_ratchet(constant: bytes, chain_key: bytes) -> Tuple[bytes, bytes]:
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
    pass

def encrypt_message(message: bytes, message_key: bytes) -> bytes:
    """Encrypt the given message using the given message key
        https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
    """
    pass 

def decrypt_message(message: bytes, message_key: bytes) -> bytes:
    """Decrypt the given message using the given message key
        https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
    """
    pass 