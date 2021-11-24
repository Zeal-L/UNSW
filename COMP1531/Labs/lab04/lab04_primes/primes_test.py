from primes import factors

def test_primes_edge_cases():
    assert factors(0) == []
    assert factors(1) == []

def test_primes_small():
    assert factors(16) == [2, 2, 2, 2]
    assert factors(21) == [3, 7]

def test_primes_large():
    assert factors(100) == [2, 2, 5, 5]
    assert factors(999999999) == [3, 3, 3, 3, 37, 333667]