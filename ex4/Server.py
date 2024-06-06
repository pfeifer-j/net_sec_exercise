#!/usr/bin/python3
import socket
import ssl
import logging

SERVER_NAME = "localhost"
SERVER_PORT = 4432

SERVER_CERT = "./openssl/server.crt"
SERVER_PRIVATE = "./openssl/server.key"
CA_CERT = "./openssl/ca.crt"

html = """
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html><html><body><h1>Hello, world!</h1></body></html>
"""

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # For Ubuntu 20.04 VM
context.load_cert_chain(SERVER_CERT, SERVER_PRIVATE)
context.load_verify_locations(CA_CERT)  # This line is important
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
sock.bind((SERVER_NAME, SERVER_PORT))  # Bind to port 4437
sock.listen(5)

logger.info("Server is running...")

while True:
    newsock, fromaddr = sock.accept()
    with context.wrap_socket(newsock, server_side=True) as ssock:
        try:
            data = ssock.recv(1024)  # Read data over TLS
            ssock.sendall(html.encode("utf-8"))  # Send data over TLS
            logger.info("Response sent to client")
        except ssl.SSLError as e:
            logger.error(f"SSL error: {e}")
        finally:
            ssock.shutdown(socket.SHUT_RDWR)  # Close the TLS connection
            ssock.close()
