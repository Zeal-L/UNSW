#! /usr/bin/env python3

import sys

dic = {}
for word in [ line.strip() for line in sys.stdin.readlines()]:
    equi = ''.join(sorted(list(word)))
    temp = dic.get(equi, [])
    temp.append(word)
    dic[equi] = temp

dic = sorted(dic.items(), key=lambda x: len(x[1]), reverse=True)

for equi in dic:
    print(f'{len(equi[1])} ', end='')
    for word in sorted(equi[1]):
        print(word, end=' ')
    print()
