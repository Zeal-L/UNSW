from math import *

def solution(a):
    number_showed = []
    showed_times = []

    for i in range(len(a)):
        if a[i] - i not in number_showed:
            number_showed.append(a[i] - i)
            showed_times.append(0)
        showed_times[number_showed.index(a[i] - i)] += 1

    result = 0
    for i in showed_times:
        if i > 1:
            result += factorial(i) // (2 * factorial(i-2))

    print(a)
    print("number_showed =>", number_showed)
    print("showed_times  =>", showed_times)
    print("Result =", result, "\n")

# Output
# [0, 1, 2, 10, 6, 4, 13]
# number_showed => [0, 7, 2, -1]
# showed_times  => [3, 2, 1, 1]
# Result = 4

# solution([0,1,2,10,6,4,13])
# solution([0,1,2,10,6,5,13])
solution([0,1,2,3,4,5,6,7])
# solution([7,6,5,4,3,2,1,0])
# solution([0,1,2,10,11,5,13])
# solution([7,1,4,9,2,5,0,1,2])
# solution([99, 100, 120])

# [0, 1, 2, 3, 4, 5, 6, 7]
# number_showed => [0]
# showed_times  => [8]
# Result = 28