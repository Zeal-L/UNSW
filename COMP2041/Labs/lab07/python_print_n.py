#!/usr/bin/env python3

import sys

payload = sys.argv[2]

for i in range(int(sys.argv[1])):
    payload = f'print({repr(payload)})'
    
print(payload)