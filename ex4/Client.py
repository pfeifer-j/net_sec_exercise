#!/usr/bin/python3
import socket, ssl, sys
import logging


hostname = "localhost"
port = 4437
cafile = "./openssl/ca.crt"

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 1
sock.connect((hostname, port))


# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # 2) # For Ubuntu 20.04 VM !
context.load_verify_locations(cafile=cafile)  # 3)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True  # Works with False


# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname)  # 4)

# Start the handshake
try:
    ssock.do_handshake()
    print("SSL handshake successful")
except ssl.SSLError as e:
    print(f"SSL handshake failed: {e}")
    ssock.close()
    sys.exit(1)

# Send a request and receive the response
request = b"GET / HTTP/1.1\r\username: test@uni.de \r\n password: test\r\n\r\n"
logger.info(request)
ssock.sendall(request)

print(ssock.recv(1024).decode())

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
