#! /usr/bin/env python3

import collections, sys

dic = collections.defaultdict(int)

for line in sys.stdin.readlines():
    dic[line.split('|')[3][:4]] += 1

print(dic['3711'])