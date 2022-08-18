#!/usr/bin/env python3

import sys
import functools

def custom(s1, s2):
    if len(s1) > len(s2):
        return 1
    elif len(s1) < len(s2):
        return -1
    else:
        if s1 > s2:
            return 1
        elif s1 < s2:
            return -1
    return 0

file = list(open(sys.argv[1], 'r'))

file.sort(key=functools.cmp_to_key(custom))

for line in file:
    print(line, end='')