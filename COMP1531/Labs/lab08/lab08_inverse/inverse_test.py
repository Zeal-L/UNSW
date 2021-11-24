from inverse import inverse
from hypothesis import given, strategies, Verbosity, settings

@given(x=strategies.integers(), y=strategies.characters())
@settings(verbosity=Verbosity.verbose)
def test_inverse(x, y):
    print(x,y)
    original = {x:y}
    expected = {y:[x]}
    assert inverse(original) == expected

def test_simple():
    assert inverse({1: 'A', 2: 'B', 3: 'A'}) == {'A': [1, 3], 'B': [2]}