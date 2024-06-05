#!/usr/bin/python3
import socket
import ssl
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HOST = 'localhost'
PORT = 4436         # Server port 4437, MIM proxy 4436

context = ssl.create_default_context(cafile="./openssl/ca.crt")

# The known good public key 
KNOWN_PUBLIC_KEY_PEM = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhSvxnQZCLcOQgQ0q74gO
r0W1sSzNK46N/iyNlfGAs0jTZCop0sCr0JF0o9IPdusuF6FeuxIp7KaDGZ9ObHYe
IHMuFB+fUg7UJHEIr4e3oVxe/nYFB5lCLahIUYLiQm99JE6UMxIzjHi57ByyFLy9
cJDJtp2lXdauNmnmCHZ0cpXdGYNnTj8xCF4DG3/Suu5cgiH3Ggd9+Nridbyrvb3k
wPhI6YJJoFSqaqXL+UrmKNmRfcnYp/Aw/8q1Uo7rOS/KjJ0Li6F7Li0EpmLzEpdv
dIFCvGxPUnZ11xPRXaoxLXQV/0DoTIiL1ntIOtVElUiU0P+jQWGBtNkC2+fCP26/
KQIDAQAB
-----END PUBLIC KEY-----
"""

def verify_server_public_key(cert):
    known_pubkey = serialization.load_pem_public_key(KNOWN_PUBLIC_KEY_PEM.encode())
    
    # extract pub key from the server's certificate
    server_pubkey = cert.public_key()
    
    # Convert both keys to PEM format
    known_pubkey_pem = known_pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).strip()
    
    server_pubkey_pem = server_pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).strip()
    
    print("Known Public Key:")
    print(known_pubkey_pem.decode())
    print("Server Public Key:")
    print(server_pubkey_pem.decode())
    
    if known_pubkey_pem == server_pubkey_pem:
        return True
    return False

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        print("SSL established. Peer:", ssock.getpeercert())
        
        # get the server's certificate 
        server_cert_binary = ssock.getpeercert(binary_form=True)
        # load the certificate
        server_cert = x509.load_der_x509_certificate(server_cert_binary)
        
        if verify_server_public_key(server_cert):
            print("Server public key is verified.")
            ssock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = ssock.recv(4096)
            print("Response received from server:")
            print(response.decode('utf-8'))
        else:
            print("Server public key verification failed.")
