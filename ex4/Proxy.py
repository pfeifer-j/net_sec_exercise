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

    logger.info("Proxy server is running...")

    while True:
        sock_for_browser, fromaddr = client_sock.accept()
        threading.Thread(
            target=handle_client, args=(sock_for_browser, context_server)
        ).start()


def handle_client(sock_for_browser, context_server):
    try:
        request = sock_for_browser.recv(2048)
        if not request:
            sock_for_browser.close()
            return

        # Check if the request is a CONNECT request
        if request.startswith(b"CONNECT"):
            handle_https_proxy(sock_for_browser, request, context_server)
        else:
            handle_http_request(sock_for_browser, request)
    except Exception as e:
        logger.error(f"Error handling client: {e}")
        sock_for_browser.close()


def handle_http_request(sock_for_browser, request):
    try:
        # Forward the HTTP request to the server and send back the response
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((SERVER_NAME, SERVER_PORT))
        server_sock.sendall(request)

        response_data = server_sock.recv(4096)
        while response_data:
            sock_for_browser.sendall(response_data)
            response_data = server_sock.recv(4096)

        server_sock.close()
    except Exception as e:
        logger.error(f"Error handling HTTP request: {e}")
    finally:
        sock_for_browser.close()


def handle_https_proxy(sock_for_browser, request, context_server):
    try:
        # Extract the host and port from the CONNECT request
        target_host_port = request.split(b" ")[1].decode()
        target_host, target_port = target_host_port.split(":")
        target_port = int(target_port)

        # Send back a success response to the client for HTTPS proxy
        sock_for_browser.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Wrap the socket for SSL
        ssock_for_browser = context_server.wrap_socket(
            sock_for_browser, server_side=True
        )

        # Establish SSL connection with the destination server
        context_client = ssl.create_default_context()
        context_client.load_verify_locations(cafile=CA_CERT)

        dest_sock = socket.create_connection((target_host, target_port))
        ssock_for_dest = context_client.wrap_socket(
            dest_sock, server_hostname=target_host
        )

        # Relay data between client and destination server
        threading.Thread(
            target=relay_data, args=(ssock_for_browser, ssock_for_dest)
        ).start()
        threading.Thread(
            target=relay_data, args=(ssock_for_dest, ssock_for_browser)
        ).start()
    except Exception as e:
        logger.error(f"Error handling HTTPS proxy: {e}")
        sock_for_browser.close()


def relay_data(sock_from, sock_to):
    try:
        while True:
            data = sock_from.recv(4096)
            if not data:
                break
            sock_to.sendall(data)
    except Exception as e:
        logger.error(f"Error relaying data: {e}")
    finally:
        sock_from.close()
        sock_to.close()


if __name__ == "__main__":
    main()
