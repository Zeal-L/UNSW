#! /usr/bin/env python3

import sys, re

regex = sys.argv[1]
file = sys.argv[2]

out = []

with open(file, "r", encoding="utf-8") as f:
    out.extend(line for line in f if re.search(regex, line))

for line in out:
    print(line, end="")