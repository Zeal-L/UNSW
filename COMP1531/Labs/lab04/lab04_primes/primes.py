import math

def factors(num):
    '''
    Returns a list containing the prime factors of 'num'. The primes should be
    listed in ascending order.

    For example:
    >>> factors(16)
    [2, 2, 2, 2]
    >>> factors(21)
    [3, 7]
    '''

    primfac = []
    d = 2
    while d*d <= num:
        while (num % d) == 0:
            primfac.append(d)
            num //= d
        d += 1
    if num > 1:
        primfac.append(num)
    return primfac

print(factors(100))
print(factors(999999999))