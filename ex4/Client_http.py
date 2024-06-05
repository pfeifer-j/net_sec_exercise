#!/usr/bin/python3
import socket
import ssl
import sys

hostname = "localhost"
port = 4436

cafile = "./openssl/ca.crt"

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(cafile=cafile)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = False

# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname)

# Start the handshake
try:
    ssock.do_handshake()
    print("SSL handshake successful")
except ssl.SSLError as e:
    print(f"SSL handshake failed: {e}")
    ssock.close()
    sys.exit(1)

# Send a request and receive the response
ssock.sendall(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
print(ssock.recv(1024).decode())

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
