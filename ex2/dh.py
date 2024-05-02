import random

'''
This group is assigned id 14.

   This prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }

   Its hexadecimal value is:

      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AACAA68 FFFFFFFF FFFFFFFF

   The generator is: 2.
'''

PRIME_MODULUS = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
GENERATOR = 2

def mod_exp(base, exponent, modulus):
    """
    Efficient modular exponentiation using the square-and-multiply algorithm.
    """
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def generate_private_key(size):
    """
    Generate a random private key of the specified size.
    """
    return random.randint(2**(size-1), 2**size - 1)

def generate_public_key(private_key):
    """
    Generate a public key based on the private key and the MODP group parameters.
    """
    return mod_exp(GENERATOR, private_key, PRIME_MODULUS)

def generate_shared_secret(private_key, other_public_key):
    """
    Generate a shared secret based on the private key and the other party's public key.
    """
    return mod_exp(other_public_key, private_key, PRIME_MODULUS)

# Generate private keys for Alice and Bob
alice_private_key = generate_private_key(2048)
bob_private_key = generate_private_key(2048)

# Generate public keys for Alice and Bob
alice_public_key = generate_public_key(alice_private_key)
bob_public_key = generate_public_key(bob_private_key)

# Alice and Bob exchange public keys and compute shared secrets
alice_shared_secret = generate_shared_secret(alice_private_key, bob_public_key)
bob_shared_secret = generate_shared_secret(bob_private_key, alice_public_key)

# Check if both shared secrets match
assert alice_shared_secret == bob_shared_secret

print("Shared secret:", alice_shared_secret)
