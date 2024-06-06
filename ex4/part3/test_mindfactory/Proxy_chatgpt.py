#!/usr/bin/python3
import socket
import ssl
import threading
import logging
import OpenSSL.crypto as crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import datetime

# Constants
LOCAL_HOST = "localhost"
CLIENT_PORT = 8081
SERVER_PORT = 443

# Paths to CA certificate and key
CERT_PATH = "./certs/"
CA_CERT_FILE = CERT_PATH + "ca.crt"
CA_KEY_FILE = CERT_PATH + "ca.key"

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.bind((LOCAL_HOST, CLIENT_PORT))
    client_sock.listen(1)

    logger.info("Proxy server is running...")

    while True:
        client_conn, client_addr = client_sock.accept()
        threading.Thread(target=handle_client, args=(client_conn,)).start()


def handle_client(client_conn):
    try:
        request = client_conn.recv(2048).decode("utf-8")
        if not request:
            return

        request_line = request.split("\n")[0]
        method, url, _ = request_line.split()

        if method == "CONNECT":
            handle_connect_method(client_conn, url)
        else:
            logger.error(f"Unsupported HTTP method: {method}")
            client_conn.close()
    except Exception as e:
        logger.error(f"Error handling client connection: {e}")
        client_conn.close()


def handle_connect_method(client_conn, url):
    try:
        server_host, server_port = url.split(":")
        server_port = int(server_port)

        server_conn = socket.create_connection((server_host, server_port))
        client_conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        ca_cert = x509.load_pem_x509_certificate(open(CA_CERT_FILE, "rb").read())
        ca_key = crypto.load_privatekey(
            crypto.FILETYPE_PEM, open(CA_KEY_FILE, "rb").read()
        )

        # Generate certificate for the server dynamically
        cert_pem, key_pem = generate_certificate(ca_cert, ca_key, server_host)

        # Wrap the client connection with SSL
        context_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context_server.load_cert_chain(certfile=cert_pem, keyfile=key_pem)
        ssl_client_conn = context_server.wrap_socket(client_conn, server_side=True)

        # Wrap the server connection with SSL
        context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context_client.load_verify_locations(CA_CERT_FILE)
        context_client.check_hostname = False
        context_client.verify_mode = ssl.CERT_NONE
        ssl_server_conn = context_client.wrap_socket(
            server_conn, server_hostname=server_host
        )

        threading.Thread(
            target=forward, args=(ssl_client_conn, ssl_server_conn)
        ).start()
        threading.Thread(
            target=forward, args=(ssl_server_conn, ssl_client_conn)
        ).start()
    except Exception as e:
        logger.error(f"Error handling CONNECT method: {e}")
        client_conn.close()


def forward(source, destination):
    try:
        while True:
            data = source.recv(2048)
            if not data:
                break
            destination.sendall(data)
    except Exception as e:
        logger.error(f"Error forwarding data: {e}")
    finally:
        source.close()
        destination.close()


def generate_certificate(ca_cert, ca_key, common_name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some-State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Locality"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem


if __name__ == "__main__":
    main()
