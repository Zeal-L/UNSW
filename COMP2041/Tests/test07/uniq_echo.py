#!/usr/bin/env python3

import sys

record = []
for word in sys.argv[1:]:
    if word not in record:
        record.append(word)
        
for word in record:
    print(word, end=' ')
    
print()