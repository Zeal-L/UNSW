def solution(n, k):
    if k == 0: return recursion(n, 0, 9)
    return recursion(n, 1, 8)

def recursion(n, odd, even):
    if n == 0: return odd, even
    return recursion(n-1, odd*9+even*1, odd*1+even*9)

for i in range(0, 7):
    print(solution(i, 0))

