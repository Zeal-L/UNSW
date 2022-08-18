#! /usr/bin/env python3

from statistics import mean, median, mode
import sys
from math import prod

nums = [int(n) for n in sys.argv[1:]]


print(f"count={len(nums)}")
print(f"unique={len(set(nums))}")
print(f"minimum={min(nums)}")
print(f"maximum={max(nums)}")
print(f"mean={mean(nums)}")
print(f"median={median(nums)}")
print(f"mode={mode(nums)}")
print(f"sum={sum(nums)}")
print(f"product={prod(nums)}")