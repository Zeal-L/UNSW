#!/usr/bin/env python3

import sys
import re

record = {}

for line in sys.stdin:
    nums = re.findall(r'-?\d+\.*\d*', line)
    if nums == []:
        continue
    nums.sort(key=float, reverse=True)
    record[line] = nums[0]

if not record:
    exit(0)
max_num = max(float(n) for n in record.values())

for key, value in record.items():
    if (float(value) == max_num):
        print(key.strip())