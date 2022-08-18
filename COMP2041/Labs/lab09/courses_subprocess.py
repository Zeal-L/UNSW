#!/usr/bin/env python3

import sys, subprocess

p = subprocess.run(rf"curl --location --silent 'http://www.timetable.unsw.edu.au/2022/{sys.argv[1]}KENS.html' | grep -E '{sys.argv[1]}.*' | sed -E 's/.*html\">(.*)<\/a>.*/\1/'", shell=True, capture_output=True, text=True, check=True)

p2 = subprocess.run(r"sed -n '{N;s/\n/\t/p}' | sort | uniq", shell=True, capture_output=True, text=True, input=p.stdout, check=True)

print(p2.stdout, end="")
