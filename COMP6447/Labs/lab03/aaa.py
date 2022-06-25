from pwn import *
from pwnlib.util.packing import p32


p = process('./runner')

#  68 65 6C 6C   6F 20 77 6F   72 6C 64 0A
payload = asm("""
    push 0x00000000
    push 0x0A646C72
    push 0x6F77206F
    push 0x6C6C6568
    
    mov eax, 0x04
    mov ebx, 0x01
    mov ecx, esp
    mov edx, 0xc

    int 0x80
""")

p.sendlineafter(b'that\n', payload)
p.interactive()
p.close()