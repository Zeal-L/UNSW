from bintrees import *
from math import *

def q1b_solution(a):
    tree = AVLTree()
    for i in range(len(a)):
        key = a[i] - i
        if not tree.__contains__(key):
            tree.insert(key, 1)
        else:
            tree.__setitem__(key, tree.__getitem__(key) + 1)

    result = 0
    for i in tree.values():
        if i > 1:
            result += factorial(i) // (2 * factorial(i-2))

    print(tree)
    print(result)

q1b_solution([0,1,2,10,6,4,13])
q1b_solution([0,1,2,3,4,5,6,7])

# Output
# AVLTree({-1: 1, 0: 3, 2: 1, 7: 2})
# 4

# AVLTree({0: 8})
# 28


# def test():
#     solution([0,1,2,10,6,4,13])
#     solution([0,1,2,10,6,5,13])
#     solution([0,1,2,3,4,5,6,7])
#     solution([7,6,5,4,3,2,1,0])
#     solution([0,1,2,10,11,5,13])
#     solution([7,1,4,9,2,5,0,1,2])
#     solution([99, 100, 120])

# from timeit import Timer

# for i in range(2, 8):
#     print(10**i, "Times")
#     t1 = Timer("test()","from Q1 import test")
#     print("my solution A: ", round(t1.timeit(number=10**i), 2), "seconds")

#     t2 = Timer("test()","from __main__ import test")
#     print("my solution B: ", round(t2.timeit(number=10**i), 2), "seconds")

