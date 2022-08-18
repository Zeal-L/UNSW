#!/usr/bin/env python3

import sys, requests
from bs4 import BeautifulSoup


res = requests.get(f"http://www.timetable.unsw.edu.au/2022/{sys.argv[1]}KENS.html")

soup = BeautifulSoup(res.text, 'html5lib')
info = soup.find_all('a')
output = {}
for i in range(len(info)):
    if sys.argv[1] in info[i].text and info[i].text not in output.keys():
        output[info[i].text] = info[i+1].text
        i += 1

for key in sorted(output.keys()):
    print(key, '\t' , output[key])