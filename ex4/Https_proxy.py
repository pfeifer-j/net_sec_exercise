#!/usr/bin/python3
# HTTPS Proxy

import socket
import ssl
import threading

# Constants
LOCAL_HOST = "localhost"
CLIENT_PORT = 8081
SERVER_HOST = "localhost"
SERVER_PORT = 4433

# Server certificate and private key
SERVER_CERT = "./openssl/server_chain.crt"
SERVER_PRIVATE = "./openssl/server.key"


def main():
    # Create a socket for the client
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.bind((LOCAL_HOST, CLIENT_PORT))
    client_sock.listen(1)

    # Load server certificate and private key
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(SERVER_CERT, SERVER_PRIVATE)

    print("Proxy server is running...")

    while True:
        sock_for_browser, fromaddr = client_sock.accept()
        sock_for_browser = context.wrap_socket(sock_for_browser,
                                               server_side=True)
        x = threading.Thread(target=process_request,
                             args=(sock_for_browser,))
        x.start()

        # Accept incoming connections from the client
        # client_conn, client_addr = client_sock.accept()

        # Receive data from the client
        # client_data = client_conn.recv(4096)

        # Create a socket for the server
        # server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # server_sock.connect((SERVER_HOST, SERVER_PORT))

        # Wrap the server socket in TLS
        # server_conn = context.wrap_socket(server_sock, server_side=False)

        # Forward client data to the server
        # server_conn.sendall(client_data)

        # Receive response from the server
        # server_resp = server_conn.recv(4096)

        # Forward server response to the client
        # client_conn.sendall(server_resp)

        # Close connections
        # server_conn.close()
        # client_conn.close()


def process_request(ssock_for_browser):
    hostname = 'www.example.com'
    # Make a connection to the real server
    sock_for_server = socket.create_connection((hostname, 443))
    # ssock_for_server = ...  # [Code omitted]: Wrap the socket using TLS
    request = ssock_for_browser.recv(2048)
    if request:
        # Forward request to server
        sock_for_server.sendall(request)
    # Get response from server, and forward it to browser
    response = sock_for_server.recv(2048)
    while response:
        ssock_for_browser.sendall(response)  # Forward to browser
        response = sock_for_server.recv(2048)
    ssock_for_browser.shutdown(socket.SHUT_RDWR)
    ssock_for_browser.close()


if __name__ == "__main__":
    main()
