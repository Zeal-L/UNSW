#!/usr/bin/env python3

import sys

num = int(sys.argv[1])
counter = 0
with open(sys.argv[2]) as file:
    for line in file:
        counter += 1
        if counter == num:
            print(line, end='')
            exit(0)