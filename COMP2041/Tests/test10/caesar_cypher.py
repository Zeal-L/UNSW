#! /usr/bin/env python3

import sys

offset = int(sys.argv[1])

for line in sys.stdin:
    for c in line:
        if c.isalpha():
            if c.isupper():
                print(chr((ord(c) - ord('A') + offset) % 26 + ord('A')), end="")
            else:
                print(chr((ord(c) - ord('a') + offset) % 26 + ord('a')), end="")
        else:
            print(c, end="")