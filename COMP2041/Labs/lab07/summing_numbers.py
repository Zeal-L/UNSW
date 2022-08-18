#!/usr/bin/env python3

import sys
import re

count = 0

with open(sys.argv[1]) as data:
    for line in data:
        for num in re.findall("\\d+", line):
            count += int(num)

print(count)