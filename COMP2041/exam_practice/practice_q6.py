#! /usr/bin/env python3

import sys

max_length = 0
for line in sys.stdin.readlines():
    temp = line
    temp[2] = temp[2].split(',')[1].strip() + ' ' + temp[2].split(',')[0].strip()
    print("{0}|{1}|{2:<{width}}|{3}|{4}".format(temp[0], temp[1], temp[2], temp[3], temp[4], width=len(temp[2]) - 1), end='')
