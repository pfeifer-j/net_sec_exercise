#!/usr/bin/python3
# HTTPS Proxy
import socket
import ssl
import threading

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
        sock_for_browser, fromaddr = client_sock.accept()
        ssock_for_browser = context_server.wrap_socket(sock_for_browser,
                                               server_side=True)
        x = threading.Thread(target=process_request,
                             args=(ssock_for_browser,))
        x.start()

        # Accept incoming connections from the client
        # client_conn, client_addr = client_sock.accept()

        # Receive data from the client
        # client_data = client_conn.recv(4096)
        #client_conn, client_addr = client_sock.accept()
        #with context_server.wrap_socket(client_conn, server_side=True) as ssock_client:
        #    client_data = ssock_client.recv(4096)




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
        response = sock_for_server.recv(2048)

        # Get response from server, and forward it to browser
        while response:
            ssock_for_browser.sendall(response)  # Forward to browser
            response = sock_for_server.recv(2048)
    ssock_for_browser.shutdown(socket.SHUT_RDWR)
    ssock_for_browser.close()




if __name__ == "__main__":
    main()
