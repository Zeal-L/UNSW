def factors(n):
    '''
    A function that generates the prime factors of n. For example
    >>> factors(12)
    [2,2,3]

    Params:
        n (int): The operand

    Returns:
        List (int): All the prime factors of n in ascending order.

    Raises:
        ValueError: When n is <= 1.
    '''
    if n <= 1:
        raise ValueError("n must be > 1")
    factors = []
    d = 2
    while n > 1:
        while n % d == 0:
            factors.append(d)
            n //= d
        d = d + 1
        if d * d > n:
            if n > 1:
                factors.append(n)
            break
    return factors


# from sympy import primefactors
# print(primefactors(8))
