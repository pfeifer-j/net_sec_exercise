#!/usr/bin/python3
# HTTPS Proxy
import socket
import ssl
import threading
import logging

# Constants
LOCAL_HOST = "localhost"
CLIENT_PORT = 8081

SERVER_HOST = "mindfactory.de"
SERVER_PORT = 8081

# Server certificate and private key
SERVER_CERT = "./new/proxy.crt"
SERVER_PRIVATE = "./new/proxy.key"

# CA certificate for verifying the server's certificate
CA_CERT = "./new/ca.crt"

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

    # Load CA certificate for verifying the server's certificate
    context_server.load_verify_locations(cafile=CA_CERT)
    context_server.verify_mode = ssl.CERT_REQUIRED

    logger.info("Proxy server is running...")

    while True:
        sock_for_browser, fromaddr = client_sock.accept()
        x = threading.Thread(
            target=process_request, args=(sock_for_browser, context_server)
        )
        x.start()


def process_request(sock_for_browser, context_server):
    # Receive the initial request from the client
    request_data = sock_for_browser.recv(1024)
    if not request_data:
        sock_for_browser.close()
        return

    # Determine if it's a HTTPS proxy request or a regular HTTP request
    if request_data.startswith(b"CONNECT"):
        handle_https_proxy(sock_for_browser, context_server)
    else:
        handle_http_request(sock_for_browser)


def handle_http_request(sock_for_browser):
    # Forward the HTTP request to the server and send back the response
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((SERVER_HOST, SERVER_PORT))
    server_sock.sendall(request_data)

    response_data = server_sock.recv(4096)
    while response_data:
        sock_for_browser.sendall(response_data)
        response_data = server_sock.recv(4096)

    server_sock.close()
    sock_for_browser.close()


def handle_https_proxy(sock_for_browser, context_server):
    # Send back a success response to the client for HTTPS proxy
    sock_for_browser.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    # Wrap the socket for SSL
    ssock_for_browser = context_server.wrap_socket(sock_for_browser, server_side=True)

    # Establish SSL connection with the destination server
    dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest_sock.connect((SERVER_HOST, SERVER_PORT))
    ssock_for_dest = context_server.wrap_socket(dest_sock)

    # Relay data between client and destination server
    threading.Thread(
        target=relay_data, args=(ssock_for_browser, ssock_for_dest)
    ).start()
    threading.Thread(
        target=relay_data, args=(ssock_for_dest, ssock_for_browser)
    ).start()


def relay_data(sock_from, sock_to):
    while True:
        data = sock_from.recv(4096)
        if not data:
            break
        sock_to.sendall(data)
    sock_from.close()
    sock_to.close()


if __name__ == "__main__":
    main()
