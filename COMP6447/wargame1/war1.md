# challenge-name: intro

## Flag
FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMS1pbnRybyIsImlwIjoiMTI0LjE4My4xOS4xNTMiLCJzZXNzaW9uIjoiYTA5ZTY0ZDYtNTljMC00Y2ViLThmNDktYzE5ZWU0NTc1MDUyIn4xNTMiLCJzZXNzaW9uIjoiYT0.1p7_Ue812O5eovGnbu85DcCY1-uJw4ZDM83AneIYFRA}

## General overview
 I didn't use "sendlineafter" at the beginning, I used "send" directly, I thought it didn't matter, the program would read it at the end. But it doesn't work, if I don't send it at a specific location, my pwn will send a lot of commands directly to the program, which will cause the program to report an error.



## Program used
```python
from pwn import *
from pwnlib.util.packing import p32, u32

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
p.sendline('cat flag')
p.interactive()
p.close()
```

======================================================

# challenge-name: too-slow

## Flag
FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMS10b28tc2xvdyIsImlwIjoiMTI0LjE4My4xOS4xNTMiLCJzZXNzaW9uIjoiOTExMjVjODgtZThhMi00ZmQxLThhYmUtZjExOTFmYTg5YmRlIn0.7ZmXXd2UnVRYIccBe1i4rqHafofpR4q8WG0zdqFCTOw}

## General overview
The challenge is interesting in that you are only given a short amount of time to answer the math questions, which is obviously impossible for humans to do. Fortunately, we have a tool like pwn, which allows us to extract the numbers directly and then send them to you after a quick local calculation.

## Program used
```python
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
```