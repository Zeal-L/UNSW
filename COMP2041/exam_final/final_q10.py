#! /usr/bin/env python3

import sys, re, collections

for line in sys.stdin.readlines():
    for word in line.split(' '):
        dic = collections.defaultdict(int)
        for i in word.strip():
            dic[i] = dic.get(i, 0) + 1
        check = list(dic.values())[0]
        pp = True
        for k in list(dic.values()):
            if check != k:
                pp = False
        if not pp:
            line = line.replace(word + ' ', '')
            line = line.replace(word, '')
    print(line, end='')

print()

