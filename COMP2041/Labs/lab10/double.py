#!/usr/bin/env python3

# calculate powers of 2 by repeated addition


i = 1
j = 1
while i < 31:
    j = j + j
    i = i + 1
    print(i, j)
