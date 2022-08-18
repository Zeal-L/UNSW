#! /usr/bin/env python3

import sys, re

num = int(sys.argv[1])

outputs = []

with open(sys.argv[2], 'r') as f:
    for line in f.readlines():
        if ' ' not in line or len(line) <= num:
            outputs.append(line)
            continue
        else:
            line = line[::-1].replace(' ', '\n', 1)[::-1]
            outputs.append(line)
            
with open(sys.argv[2], 'w') as f:
    for line in outputs:
        f.write(line)
        
