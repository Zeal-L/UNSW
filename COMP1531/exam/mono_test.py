from mono import monotonic
import pytest

def test_1():
    data = [(1,3,2),(1,2)]
    out = ['neither', 'monotonically increasing']
    assert monotonic(data) == out

def test_2():
    data = [(1,3,2),(1,2),(3,2,1)]
    out = ['neither', 'monotonically increasing', 'monotonically decreasing']
    assert monotonic(data) == out

def test_3():
    with pytest.raises(ValueError):
        data = [(1,3,100000),(1,2),(3,2,1)]
        monotonic(data)

def test_4():
    with pytest.raises(ValueError):
        data = [(1),(1,2),(3,2,1)]
        monotonic(data)