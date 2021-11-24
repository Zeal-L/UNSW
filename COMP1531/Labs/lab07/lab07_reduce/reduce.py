def reduce(f, xs):
    xs = list(xs)
    if (len(xs) == 1):
        return xs[0]
    last = xs.pop()
    return f(reduce(f, xs), last)
