#! /usr/bin/env python3

import sys, re, subprocess

for line in sys.stdin.readlines():
    if info := re.findall(r'([^>]*)<!(.*?)>([^<]*)', line):
        for single in info:
            res = subprocess.run(single[1], check=True, shell=True, capture_output=True, text=True)
            print(single[0], res.stdout, single[2], sep='', end='')
    elif info := re.findall(r'([^>]*)<(.*?)>([^<]*)', line):
        for single in info:
            res = subprocess.run(f"cat {single[1]}", check=True, shell=True, capture_output=True, text=True)
            print(single[0], res.stdout, single[2], sep='', end='')
    else:    
        print(line, end='')