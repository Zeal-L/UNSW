from factors import factors, is_prime
from hypothesis import given, strategies
import pytest

@given(strategies.integers(min_value=2, max_value=1000))
def test_factors(n):
    '''
    Ensure the factors of n multiply to give n.
    '''
    product = 1
    for f in factors(n):
        product *= f
    assert product == n

@given(strategies.integers(min_value=2, max_value=1000))
def test_ascending(n):
    '''
    Ensure the factors are in ascending order.
    '''
    prev = None
    for f in factors(n):
        if prev:
            assert f >= prev
        prev = f

@given(strategies.integers(min_value=2, max_value=1000))
def test_prime(n):
    '''
    All the factors should be prime numbers.
    '''
    for f in factors(n):
        assert is_prime(f)

@given(strategies.integers(max_value = 1))
def test_error(n):
    '''
    Numbers less than or equal to 1 don't have prime factors.
    '''
    with pytest.raises(ValueError):
        list(factors(n))
