#! /usr/bin/env python3

import sys

inputs = sys.stdin.readlines()
for line in inputs:
    if line.startswith("#"):
        print(inputs[int(line[1])-1], end="")
    else:
        print(line, end="")