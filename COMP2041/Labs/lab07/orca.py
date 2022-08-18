#!/usr/bin/env python3

import sys

count = 0

for arg in sys.argv[1:]:
    with open(arg) as data:
        for line in data:
            if "Orca" in line:
                count += int(line.split()[1])


print(count, "Orcas reported")
