from drykiss import drykiss

def test_sequence():
    assert drykiss([1, 2, 3, 4, 5]) == (1, 24, 120)

def test_reverse():
    assert drykiss([5, 4, 3, 2, 1]) == (1, 120, 24)

def test_random():
    assert drykiss([2, 8, 3, 10, 42]) == (2, 2 * 8 * 3 * 10, 8 * 3 * 10 * 42)

def test_negative():
    assert drykiss([-2, -8, -3, -10, -42]) == (-42, 2 * 8 * 3 * 10, 8 * 3 * 10 * 42)

def test_integers():
    assert drykiss([-2, 8, -3, -10, 42]) == (-10, -2 * 8 * 3 * 10, 8 * 3 * 10 * 42)

def test_decimals():
    assert drykiss([-0.5, 8, -0.9, -10.9, 42]) == (-10.9, -0.5 * 8 * 0.9 * 10.9, 8 * 0.9 * 10.9 * 42)
