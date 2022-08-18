#!/usr/bin/env python3

import sys

times = int(sys.argv[1])
record = {}

for line in sys.stdin:
    if (record.get(line) == None):
        record[line] = 1
    else:
        record[line] = record[line] + 1
    if (record.get(line) >= times):
        print("Snap: " + line.strip())
        break