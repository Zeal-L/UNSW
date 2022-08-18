#!/usr/bin/env python3
import sys
import re

target = sys.argv[1].strip()

count = 0
for line in sys.stdin:
    words = re.findall(rf"\b{target}\b", line, flags=re.I)
    count += len(words)

print(target, "occurred", count, "times")

