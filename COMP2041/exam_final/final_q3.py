#! /usr/bin/env python3

import sys


dic = set()

for line in sys.stdin.readlines():
    if line[-2] == 'M':
        temp1 = line.split('|')
        temp2 = temp1[2].split(',')
        dic.add(temp2[0])
        
for i in sorted(dic):
    print(i)