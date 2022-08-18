#! /usr/bin/env python3

import collections
import sys

max_n = int(sys.argv[1])

dic = collections.defaultdict(int)

count = 0
while line := sys.stdin.readline().replace(" ", "").lower():
    dic[line] += 1
    count += 1
    if len(dic) >= max_n:
        print(f"{len(dic)} distinct lines seen after {count} lines read.")
        exit(0)

print(f"End of input reached after {count} lines read - {max_n} different lines not seen.")
