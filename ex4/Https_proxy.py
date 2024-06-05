#!/usr/bin/python3
# HTTPS Proxy
import socket
import ssl

# Constants
LOCAL_HOST = "localhost"
CLIENT_PORT = 4436
SERVER_HOST = "localhost"
SERVER_PORT = 4437

# Server certificate and private key
SERVER_CERT = "./openssl/proxy.crt"
SERVER_PRIVATE = "./openssl/proxy.key"


# CA certificate for verifying the server's certificate
CA_CERT = "./openssl/ca.crt"


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
    context_client.load_verify_locations(cafile="./openssl/proxy.crt")

    print("Proxy server is running...")

    while True:
        # Accept incoming connections from the client
        client_conn, client_addr = client_sock.accept()
        with context_server.wrap_socket(client_conn, server_side=True) as ssock_client:
            client_data = ssock_client.recv(4096)

            # Create a socket for the server
            with socket.create_connection((SERVER_HOST, SERVER_PORT)) as server_sock:
                with context_client.wrap_socket(
                    server_sock, server_hostname=SERVER_HOST
                ) as ssock_server:
                    # Forward client data to the server
                    ssock_server.sendall(client_data)

                    # Receive response from the server
                    server_resp = ssock_server.recv(4096)

                    # Forward server response to the client
                    ssock_client.sendall(server_resp)


if __name__ == "__main__":
    main()
