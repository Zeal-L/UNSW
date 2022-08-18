#!/usr/bin/env python3

import sys

with open(sys.argv[1], 'r') as file:
    l = list(file)
    if not (count := len(l)):
        exit(0)
    if count % 2 == 0:
        print(l[(count // 2) - 1], end='')
    print(l[count // 2], end='')