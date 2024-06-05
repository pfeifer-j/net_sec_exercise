import socket
import ssl
import sys


def create_tls_socket(server_hostname):
    # Create a new socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Obtain the default SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED

    # Load CA certificates (root certificate)
    cadir = "./openssl"
    cafile = "./openssl/ca.crt"
    # context.load_verify_locations(cafile="./certs/ca-certificates.crt")
    context.load_verify_locations(capath=cadir)

    # Wrap the socket into an SSLSocket
    try:
        secure_socket = context.wrap_socket(
            client_socket, server_hostname=server_hostname
        )
        return secure_socket
    except ssl.SSLError as e:
        print(f"Error creating SSLSocket: {e}")
        sys.exit(1)


if __name__ == "__main__":

    server_hostname = "localhost"
    secure_socket = create_tls_socket(server_hostname)

    # Now you can use secure_socket to communicate with the server
    # For example, connect to an HTTPS-based web server:
    secure_socket.connect((server_hostname, 4433))
    secure_socket.sendall(
        b"GET / HTTP/1.1\r\nHost: " + server_hostname.encode() + b"\r\n\r\n"
    )
    response = secure_socket.recv(4096)
    print(response.decode())

    # Close the socket
    secure_socket.close()
