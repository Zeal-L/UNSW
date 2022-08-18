#!/usr/bin/env python3

import sys
import re

for word in sys.argv[1:]:
    if re.findall(r'[aeiou]{3}', word, re.I):
        print(word, end=' ')
print()