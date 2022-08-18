#!/usr/bin/env python3

import sys

count = 0

dic={}

for arg in sys.argv[1:]:
    with open(arg) as data:
        for line in data:
            line = line.lower().strip()
            key =  ' '.join(line.split(maxsplit=2)[-1].split())
            if 's' == key[-1]:
                key = key[:-1]
            if not dic.get(key):
                dic[key] = [1, int(line.split()[1])]
            else:
                left = dic[key][0]
                right = dic[key][1]
                dic[key] = [left + 1, right + int(line.split()[1])]

ordered = sorted(dic.keys())
for key in ordered:
    print(key, "observations:", dic[key][0], "pods,", dic[key][1], "individuals")