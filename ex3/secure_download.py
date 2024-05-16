"""
exercise 3.2.1
@Authors: Noah Link, Jan Pfeifer, Julian Weske
"""

import socket


# exercise 2.1
def part_one():
    # Send data request to the server
    data_request_hex = "010a00013d07e50004770473840100012e"
    client_socket.sendall(bytes.fromhex(data_request_hex))
    print("Data request sent: ", bytes.fromhex(data_request_hex))
    response = client_socket.recv(4096)
    print("Data response from server:", response)
    print("\n##########################\n")


# exercise 2.2
def part_two():
    file_request_hex = (
        "01 0a00013d 07e50019 7704739901 0013 73656375726974792d7265706f72742e747874000000"  # Change 0016 to 0013 and pad with 000000
    ).replace(" ", "")
    client_socket.sendall(bytes.fromhex(file_request_hex))
    print("File request sent: \n\n", bytes.fromhex(file_request_hex))
    response = client_socket.recv(4096)

    # Replace Unicode box drawing characters with ASCII equivalents to display Figure 1 correctly
    try:
        response = response.decode("utf-8")
    except UnicodeDecodeError:
        response = response.decode("utf-8", errors="ignore")
    response = response.replace("┌", "+").replace("┬", "+").replace("┐", "+")
    response = response.replace("├", "+").replace("┼", "+").replace("┤", "+")
    response = response.replace("└", "+").replace("┴", "+").replace("┘", "+")
    response = response.replace("│", "|").replace("─", "-")

    print("File response from server:", response)


# exercise 3.1.2
def calculate_mac(header_data: bytes, key=(0x7C, 0x38, 0x91, 0x80)) -> bytes:
    mac = []
    mac.append(key[0] ^ header_data[0] ^ header_data[1] ^ header_data[2])
    mac.append(key[1] ^ header_data[3] ^ header_data[4])
    mac.append(key[2] ^ header_data[5] ^ header_data[6])
    mac.append(key[3] ^ header_data[7] ^ header_data[8])
    return bytes(mac)


# exercise 3.2.1
def part_three(command_type, ip, port, length, command):
    header = command_type + ip + port + length
    mac = calculate_mac(bytes.fromhex(header))
    file_request = header + mac.hex() + command
    request_hex = bytes.fromhex(file_request)

    client_socket.sendall(request_hex)
    response = client_socket.recv(4096)
    print("File response from server:", response)


# exercise 3.2.3
def part_four():
    command_type = "01"
    ip = "0a00037f"
    port = "07e5"
    length = "000c"
    header = command_type + ip + port + length
    mac = calculate_mac(bytes.fromhex(header))
    command = "01000970726f6f662e747874"
    file_request = header + mac.hex() + command
    request_hex = bytes.fromhex(file_request)

    client_socket.sendall(request_hex)
    print("File request sent: \n\n", request_hex)
    response = client_socket.recv(4096)
    print("File response from server:", response)


if __name__ == "__main__":
    HOST = "195.37.209.19"
    PORT = 7213

    # Create a socket object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:

        # Connect to the server
        client_socket.connect((HOST, PORT))
        print("Connection established with server.")

        # exercise 2.1
        part_one()

        # exercise 2.2
        part_two()

        # exercise 3.2.1
        part_three("01", "0a00037f", "07e5", "000c", "01000970726f6f662e747874")

        # exercise 3.2.3
        part_four()
