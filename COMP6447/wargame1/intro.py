from pwn import *
from pwnlib.util.packing import p32, u32


# context.terminal = ['tmux','splitw','-h']
# context(os='windows', arch='arm', log_level='debug')

p = remote('comp6447.wtf', 20478)

p.recvuntil(b'{')
number = int(p.recvuntil(b'}', drop=True), 16)

p.sendlineafter(b'form!\n', bytes(str(number), 'utf-8'))
p.sendlineafter(b'0x103!\n', bytes(hex(number - 0x103), 'utf-8'))

p.recvuntil(b'me ')
number = int(p.recvuntil(b' ', drop=True), 16)
p.sendlineafter(b'form!\n', p32(number))

p.recvuntil(b')\n')
address = p.recvline().strip()

p.sendlineafter(b'form!\n', str(u32(address)))
p.sendlineafter(b'form!\n', hex(u32(address)))

p.recvuntil(b'is ')
num1 = int(p.recvuntil(b' +', drop=True))
num2 = int(p.recvuntil(b'?', drop=True))
p.sendlineafter(b'\n', str(num1 + num2))

p.sendlineafter(b'?\n', 'password\n')
# p.sendline('cat flag')

p.interactive()
p.close()