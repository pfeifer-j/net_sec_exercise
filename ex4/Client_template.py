#!/usr/bin/python3
import socket, ssl, sys, pprint

hostname = sys.argv[1]
port = 443
cadir = '/etc/ssl/certs'


# Create TCP connection
#1
sock.connect((hostname, port))


# Set up the TLS context
context = ssl.SSLContext(#2) # For Ubuntu 20.04 VM !
context.load_verify_locations(#3)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True


# Add the TLS
ssock = context.wrap_socket(#4)

# Start the handshake
ssock.do_handshake()

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
