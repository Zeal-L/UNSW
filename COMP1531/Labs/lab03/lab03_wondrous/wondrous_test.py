from wondrous import wondrous

def test_basic():
    assert wondrous(5) == [5, 16, 8, 4, 2, 1]
    assert wondrous(4) == [4, 2, 1]
    assert wondrous(3) == [3, 10, 5, 16, 8, 4, 2, 1]
    assert wondrous(2) == [2, 1]

def test_zero():
    assert wondrous(0) == [0]
