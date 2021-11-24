from transpose import transpose
import pytest

def test_0x0():
    assert transpose([[]]) == [[]]

def test_1x1():
    assert transpose([[1]]) == [[1]]

def test_2x1():
    assert transpose([[1,2]]) == [[1],[2]]

def test_2x2():
    assert transpose([[1,2], [3,4]]) == [[1,3], [2,4]]

def test_2x3():
    assert transpose([[1,2], [3,4], [5,6]]) == [[1,3,5], [2,4,6]]

def test_3x3():
    assert transpose([[1,2,3], [4,5,6], [7,8,9]]) == [[1,4,7], [2,5,8], [3,6,9]]

def test_3x3_not_the_same_length():
    with pytest.raises(ValueError):
        transpose([[1,2,3], [4,5,6], [7,8]])
