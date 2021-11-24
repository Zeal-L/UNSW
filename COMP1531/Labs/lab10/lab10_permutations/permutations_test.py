from permutations import permutations
from hypothesis import given, strategies, assume

from math import factorial

@given(strategies.text(min_size=1, max_size=7))
def test_permutation(string):
    '''
    Every string in the set should be a permutation of the input string.
    '''
    for p in permutations(string):
        assert sorted(p) == sorted(string)

@given(strategies.text(min_size=1, max_size=7))
def test_size(string):
    '''
    For a string of length n the number of permutations is determined by the number of characters
    that repeat.
    '''
    sz = factorial(len(string))
    for c in set(string):
        sz = sz / factorial(string.count(c))
    assert len(permutations(string)) == sz
