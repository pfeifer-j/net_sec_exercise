#!/usr/bin/python3
# HTTPS Proxy

import socket
import ssl

# Constants
LOCAL_HOST = "localhost"
CLIENT_PORT = 8080
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
        # Accept incoming connections from the client
        client_conn, client_addr = client_sock.accept()

        # Receive data from the client
        client_data = client_conn.recv(4096)

        # Create a socket for the server
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((SERVER_HOST, SERVER_PORT))

        # Wrap the server socket in TLS
        server_conn = context.wrap_socket(server_sock, server_side=False)

        # Forward client data to the server
        server_conn.sendall(client_data)

        # Receive response from the server
        server_resp = server_conn.recv(4096)

        # Forward server response to the client
        client_conn.sendall(server_resp)

        # Close connections
        server_conn.close()
        client_conn.close()


if __name__ == "__main__":
    main()
