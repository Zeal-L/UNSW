from math import *

def solution(a):
    aa = [0] * ((len(a) + 1) * 2)
    for i in range(len(a)):
        if a[i] - i >= 0:
            aa[a[i] - i] += 1
        if a[i] - i < 0:
            aa[-(a[i] - i) + len(a) - 1] += 1

    result = 0
    for i in aa:
        if i > 1:
            result += factorial(i) // (2 * factorial(i-2))
    print(a, " => ", aa)
    print("Result = ", result)

a = [0,1,2,10,6,4,13]
b = [0,1,2,10,6,5,13]
c = [0,1,2,3,4,5,6,7]
d = [7,6,5,4,3,2,1,0]
e = [0,1,2,10,11,5,13]

new = [7,1,4,9,2,5,0,1,2]

# solution(a)
# solution(b)
# solution(c)
# solution(d)
# solution(e)
solution(new)
