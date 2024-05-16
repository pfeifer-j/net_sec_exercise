import socket
import time
from concurrent.futures import ThreadPoolExecutor


# Calculate mac
def calculate_mac(header_data: bytes, key=(0x7C, 0x38, 0x91, 0x80)) -> bytes:
    mac = list()
    mac.append(key[0] ^ header_data[0] ^ header_data[1] ^ header_data[2])
    mac.append(key[1] ^ header_data[3] ^ header_data[4])
    mac.append(key[2] ^ header_data[5] ^ header_data[6])
    mac.append(key[3] ^ header_data[7] ^ header_data[8])
    return bytes(mac)


def process_ip(ip):
    HOST = "195.37.209.19"
    PORT = 7213

    header = bytes.fromhex("01" + ip + "07e50004")
    mac = calculate_mac(header)
    list_files_command = "770473840100012e"

    data_request_hex = header.hex() + mac.hex() + list_files_command
    print(ip)

    # Create a socket object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:

        # Connect to the server
        client_socket.connect((HOST, PORT))
        client_socket.sendall(bytes.fromhex(data_request_hex.replace(" ", "")))
        response = client_socket.recv(4096)

        # Print response only if the server responds
        if response:
            ip_list.append(ip)
            print("Data response from server:", response)


if __name__ == "__main__":
    ip_list = []

    with ThreadPoolExecutor() as executor:
        for i in range(16):
            for j in range(256):
                ip = "0a00{:02x}{:02x}".format(i, j)
                executor.submit(process_ip, ip)
