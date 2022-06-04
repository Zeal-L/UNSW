from pwn import *
from pwnlib.util.packing import p32, u32

def plus(p):
    p.recvuntil(b'!\n')
    number1 = p.recvuntil(b' ', drop=True)
    p.recvuntil(b' ')
    number2 = p.recvuntil(b' ', drop=True)
    p.sendlineafter(b'=', str(int(number1)+int(number2)))

p = remote('comp6447.wtf', 20677)

for i in range(10):
    plus(p)


p.sendline('cat flag')

p.interactive()
p.close()