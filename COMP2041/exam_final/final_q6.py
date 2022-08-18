#! /usr/bin/env python3

import sys

f1 = open(sys.argv[1], 'r').readlines()
f2 = open(sys.argv[2], 'r').readlines()

f2 = f2[::-1]

if len(f1) != len(f2):
    print(f"Not mirrored: different number of lines: {len(f1)} versus {len(f2)}")
    sys.exit(1)
    

for i in range(len(f1)):
    if f1[i].strip() != f2[i].strip():
        print(f"Not mirrored: line {i+1} different")
        sys.exit(1)

print("Mirrored")

