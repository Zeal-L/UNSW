import pytest
from factors import factors
from hypothesis import given, strategies, Verbosity, settings

def test_error():
    with pytest.raises(Exception):
        factors(1)

@given(strategies.integers(min_value=2, max_value=10000))
@settings(verbosity=Verbosity.verbose)
def test_factors(n):
    result = factors(n)
    for i in result:
        assert n % i == 0

def test_simple_example():
    assert factors(2) == [2]
    assert factors(3) == [3]
    assert factors(4) == [2, 2]
    assert factors(5) == [5]
    assert factors(6) == [2, 3]
    assert factors(7) == [7]
    assert factors(8) == [2, 2, 2]
    assert factors(9) == [3, 3]
    assert factors(10) == [2, 5]
