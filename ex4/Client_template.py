#!/usr/bin/python3
import socket, ssl, sys, pprint

hostname = sys.argv[1]
port = 443
cadir = './certs'


# Create TCP connection
#1
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))


# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True


# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname)

# Start the handshake
ssock.do_handshake()

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
