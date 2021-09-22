def solution(a, m):

    table = [0] * m
    for i in a:
        table[i - 1] += 1

    print(a)
    # print(table)
    print("The Beauty is", min(table))

# solution([1, 3, 2, 3, 3, 2], 3)
solution([1, 3, 1, 2, 3, 3, 2], 3)
# solution([1, 3, 1, 2, 3, 3, 2, 2, 2, 1], 3)
# solution([1, 3, 1, 2, 3, 3, 2], 4)