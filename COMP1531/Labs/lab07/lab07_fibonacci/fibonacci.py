def fib(n):
    if n == 1:
        return [1]
    if n == 2:
        return [1, 1]
    fibs = [1, 1]
    i = 2
    while i < n-1:
        fibs.append(fibs[-1] + fibs[-2])
        i = i + 1
    return fibs
