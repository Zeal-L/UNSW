#!/usr/bin/env python3

import glob
from math import log
import os
import sys
import re

def total_words(f):
    count = 0
    for line in f:
        words = re.findall(r"\W?([a-zA-Z]+)\W?", line)
        count += len(words)
    return count

def count_word(f, w):
    count = 1
    for line in f:
        words = re.findall(rf"\b{w}\b", line, flags=re.I)
        count += len(words)
    return count

def frequency(f, w):
    cw = count_word(open(f), w)
    tw = total_words(open(f))
    return cw/tw


for file in sorted(glob.glob("lyrics/*.txt")):
    fre = []
    for word in sys.argv[1:]:
        fre.append(frequency(file, word))

    probability = 0
    for i in fre:
        probability += log(i)
    filename = os.path.basename(file).replace(".txt", "").replace("_", " ")
    print(f"{probability:10.5f} {filename}")

