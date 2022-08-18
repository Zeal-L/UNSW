#!/usr/bin/env python3
import sys
import re

count = 0
for line in sys.stdin:
    words = re.findall(r"\W?([a-zA-Z]+)\W?", line)
    count += len(words)
    
print(count, "words")

