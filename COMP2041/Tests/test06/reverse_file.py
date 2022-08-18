#!/usr/bin/env python3

import sys

data = []

with open(sys.argv[1]) as file:
    for line in file:
        data.append(line)

data.reverse()

with open(sys.argv[2], 'a') as file:
    for line in data:
        file.writelines(line)