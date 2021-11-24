import pytest
from neighbours import neighbours
import inspect

def test_generator():
    '''
    Ensure it is generator function
    '''
    assert inspect.isgeneratorfunction(neighbours), "neighbours does not appear to be a generator"

def test_empty():
    assert list(neighbours([])) == []

def test_singleton():
    assert list(neighbours([1])) == [(1,)]

def test_two():
    assert list(neighbours([1,2])) == [(1,2), (1,2)]

def test_simple():
    assert list(neighbours([1,2,3,4])) == [(1,2), (1,2,3), (2,3,4), (3,4)]

def test_explicit_iterator():
    # Note that this is not quite the same as the test above
    assert list(neighbours(iter([1,2,3,4]))) == [(1,2), (1,2,3), (2,3,4), (3,4)]

def test_nonlist():
    assert list(neighbours("hey")) == [('h','e'), ('h', 'e', 'y'), ('e', 'y')]

def test_productive():
    '''
    This test checks that the generator function does not evaluate the entire input iterator before producing a result.
    '''
    def failing_gen():
        yield from [1,2,3]
        raise ValueError("This generator fails after yield 3 elements")

    actual = neighbours(failing_gen())
    assert next(actual) == (1,2)
    assert next(actual) == (1,2,3)
    with pytest.raises(ValueError):
        next(actual)
