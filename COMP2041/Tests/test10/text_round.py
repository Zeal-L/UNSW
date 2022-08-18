#! /usr/bin/env python3

import sys, re


inputs = sys.stdin.readlines()
for line in inputs:
    print(re.sub(r'\d+\.?\d*', lambda xs: str(round(float(xs.group(0)))), line), end="")