#!/usr/bin/env python3
import glob
import sys
import re
import os

target = sys.argv[1].strip()

def total_words(f):
    count = 0
    for line in f:
        words = re.findall(r"\W?([a-zA-Z]+)\W?", line)
        count += len(words)
    return count

def count_word(f, word):
    count = 0
    for line in f:
        words = re.findall(rf"\b{word}\b", line, flags=re.I)
        count += len(words)
    return count

for file in sorted(glob.glob("lyrics/*.txt")):
    cw = count_word(open(file), target)
    tw = total_words(open(file))
    filename = os.path.basename(file).replace(".txt", "").replace("_", " ")
    print(f"{cw:4}/{tw:6} = {cw/tw:.9f} {filename}")