#!/usr/bin/python3
import socket
import ssl
import threading

# Constants
LOCAL_HOST = "localhost"
CLIENT_PORT = 4436
SERVER_HOST = "localhost"
SERVER_PORT = 4437

# Proxy certificate and private key
PROXY_CERT = "./openssl/proxy.crt"
PROXY_KEY = "./openssl/proxy.key"

# CA certificate for verifying server and client certificates
CA_CERT = "./openssl/ca.crt"


def process_request(ssock_client):
    try:
        # Create a socket for the server
        with socket.create_connection((SERVER_HOST, SERVER_PORT)) as server_sock:
            context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context_client.load_verify_locations(cafile=CA_CERT)
            with context_client.wrap_socket(
                server_sock, server_hostname=SERVER_HOST
            ) as ssock_server:
                client_data = ssock_client.recv(4096)
                if client_data:
                    # Forward client data to the server
                    ssock_server.sendall(client_data)

                    # Receive response from the server and forward to the client
                    server_resp = ssock_server.recv(4096)
                    while server_resp:
                        ssock_client.sendall(server_resp)
                        server_resp = ssock_server.recv(4096)
    except Exception as e:
        print(f"Error processing request: {e}")
    finally:
        ssock_client.shutdown(socket.SHUT_RDWR)
        ssock_client.close()


def main():
    # Create a socket for the client
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.bind((LOCAL_HOST, CLIENT_PORT))
    client_sock.listen(5)

    context_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context_server.load_cert_chain(certfile=PROXY_CERT, keyfile=PROXY_KEY)
    context_server.load_verify_locations(cafile=CA_CERT)
    context_server.verify_mode = ssl.CERT_OPTIONAL

    print("Proxy server is running...")

    while True:
        client_conn, client_addr = client_sock.accept()
        ssock_client = context_server.wrap_socket(client_conn, server_side=True)
        threading.Thread(target=process_request, args=(ssock_client,)).start()


if __name__ == "__main__":
    main()
