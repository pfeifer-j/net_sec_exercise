# Client
import socket
import ssl

hostname = "127.0.0.1"  # Proxy's address
port = 8080  # Proxy's port

cafile = "./openssl/ca.crt"
# cafile = "/etc/ssl/certs/ca-certificates.crt"

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(cafile=cafile)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssock = context.wrap_socket(sock, server_hostname=hostname)

ssock.connect((hostname, port))

ssock.sendall(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
print(ssock.recv(4096).decode())

ssock.close()
