from reduce import reduce

def test_reduce_plus():
    assert reduce(lambda x, y: x + y, [1,2,3,4,5]) == 15

def test_reduce_plus_letter():
    assert reduce(lambda x, y: x + y, 'abcdefg') == 'abcdefg'

def test_reduce_times():
    assert reduce(lambda x, y: x * y, [1,2,3,4,5]) == 120