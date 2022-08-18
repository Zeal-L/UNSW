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

def frequency(f, w, tw):
    cw = count_word(open(f), w)
    return cw/tw

def logProbability(to_compare):
    dic = {}
    for artist_file in sorted(glob.glob("lyrics/*.txt")):
        fre = []
        tw = total_words(open(artist_file))
        for line in open(to_compare):
            for word in re.findall(r"\W?([a-zA-Z]+)\W?", line):
                fre.append(frequency(artist_file, word, tw))
        probability = 0
        for i in fre:
            probability += log(i)
        artist_name = os.path.basename(artist_file).replace(".txt", "").replace("_", " ")
        dic[artist_name] = probability
    probability = max(dic.values())
    new_dic = {v : k for k, v in dic.items()}
    return new_dic.get(probability), probability


for file in sys.argv[1:]:
    artist, prob = logProbability(file)
    print(f"{file} most resembles the work of {artist} (log-probability={round(prob, 1)})")
