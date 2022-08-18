#! /usr/bin/env python3
import sys
from re import match


for line in sys.stdin.readlines():
    if "#!/bin/bash" in line:
        print("#!/usr/bin/env python3")
    
    elif line == '\n':
        print("")
    
    elif match(r"^\s*#", line):
        print(line)
    
    elif info := match(r"(\s*)(\w+)=([\$]*\w+)", line):
        print(f"{info.group(1)}{info.group(2)} = {info.group(3).replace('$', '')}")
    
    elif info := match(r"(.*)while \(\((.*)\)\)", line):
        print(f"{info.group(1)}while {info.group(2)}:")
    
    elif info := match(r"(.+)=\$\(\((.+)\)\)$", line):
        print(f"{info.group(1)} = {info.group(2).replace('/', '//')}")
    
    elif info := match(r"^(.*)echo \$(.+)", line):
        print(f"{info.group(1)}print({info.group(2).replace(' $', ', ')})")
    
    elif info := match(r"^(.*)if \(\((.+)\)\)", line):
        print(f"{info.group(1)}if {info.group(2)}:")
        
    elif info := match(r"^(.*)else", line):
        print(f"{info.group(1)}else:")
    



