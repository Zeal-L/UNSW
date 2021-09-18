from math import *

def solution(a):
    aa = [0] * (len(a) + 1)
    for i in range(len(a)):
        if a[i] - i >= 0:
            aa[a[i] - i] += 1

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

solution(a)
solution(b)
solution(c)
solution(d)
solution(e)
