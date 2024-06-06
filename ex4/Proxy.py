#!/usr/bin/python3
# HTTPS Proxy
import socket
import ssl
import threading
import logging

# Constants
LOCAL_HOST = "localhost"
CLIENT_PORT = 4431
SERVER_NAME = "localhost"
SERVER_PORT = 4432

# Server certificate and private key
CERT_PATH = "./openssl/"
SERVER_CERT = CERT_PATH + "proxy.crt"
SERVER_PRIVATE = CERT_PATH + "proxy.key"
CA_CERT = CERT_PATH + "ca.crt"

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    # Create a socket for the client
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.bind((LOCAL_HOST, CLIENT_PORT))
    client_sock.listen(1)

    # Load server certificate and private key
    context_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context_server.load_cert_chain(SERVER_CERT, SERVER_PRIVATE)

    # Load client certificate settings for connecting to the actual server
    context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context_client.load_verify_locations(cafile="./openssl/ca.crt")
    context_client.load_cert_chain(
        certfile="./openssl/proxy.crt", keyfile="./openssl/proxy.key"
    )

    logger.info("Proxy server is running...")

    while True:
        sock_for_browser, fromaddr = client_sock.accept()
        ssock_for_browser = context_server.wrap_socket(
            sock_for_browser, server_side=True
        )
        x = threading.Thread(
            target=process_request, args=(ssock_for_browser, context_client)
        )
        x.start()


def process_request(ssock_for_browser, context_client):
    # Make a connection to the real server
    server_sock = socket.create_connection((SERVER_HOST, SERVER_PORT))
    sock_for_server = context_client.wrap_socket(
        server_sock, server_hostname=SERVER_HOST
    )
    request = ssock_for_browser.recv(2048)

    if request:
        # Forward request to server
        sock_for_server.sendall(request)
        logger.info("Response sent to client")
        logger.info(request)
        response = sock_for_server.recv(2048)

        # Get response from server, and forward it to browser
        while response:
            ssock_for_browser.sendall(response)  # Forward to browser
            response = sock_for_server.recv(2048)
    ssock_for_browser.shutdown(socket.SHUT_RDWR)
    ssock_for_browser.close()


if __name__ == "__main__":
    main()
