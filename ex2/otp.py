import os
# Network Security — Exercise 2: Cryptographic Protocols
# Noah Link, Jan Pfeifer

def generate_key(message_length):
    return bytes([os.urandom(1)[0] for _ in range(message_length)])

def encrypt(message, key):
    if len(message) != len(key):
        raise ValueError("Message and key must be of the same length")

    encrypted_message = b""
    for m, k in zip(message, key):
        encrypted_message += bytes([(m + k) % 256])
    return encrypted_message

def decrypt(encrypted_message, key):
    if len(encrypted_message) != len(key):
        raise ValueError("Message and key must be of the same length")

    decrypted_message = b""
    for em, k in zip(encrypted_message, key):
        decrypted_message += bytes([(em - k) % 256])
    return decrypted_message

def alter_ciphertext(ciphertext, position, alteration):
    altered_ciphertext = bytearray(ciphertext)
    altered_ciphertext[position] = (altered_ciphertext[position] + alteration) % 256
    return bytes(altered_ciphertext)

# Example usage:
'''
Conduct an Experiment
- Encrypt and Display: Encrypt a sample plaintext and show the ciphertext.
'''
message = b"I like cooking, my family, and my pets."
key = generate_key(len(message))
encrypted_message = encrypt(message, key)
decrypted_message = decrypt(encrypted_message, key)

print("Original message: ", message)
# print("Key: ", key())
print("Encrypted message: ", encrypted_message)
# print("Decrypted message:", decrypted_message.decode())

'''
- Manipulate Ciphertext: Use the manipulate function to alter the ciphertext.
- Decrypt and Explain: Decrypt the manipulated ciphertext, display the altered
plaintext, and explain the results.
'''
altered_position = 14
alteration_value = -12
altered_ciphertext = alter_ciphertext(encrypted_message, altered_position, alteration_value)

altered_position = 25
alteration_value = -12
altered_ciphertext = alter_ciphertext(altered_ciphertext, altered_position, alteration_value)
altered_plaintext = decrypt(altered_ciphertext, key)

print("Altered ciphertext: ", altered_ciphertext)
print("Altered plaintext: ", altered_plaintext.decode())