from fibonacci import fib

def test_one():
    assert fib(1) == [1]

def test_two():
    assert fib(2) == [1, 1]

def test_small():
    assert fib(10) == [1, 1, 2, 3, 5, 8, 13, 21, 34]

def test_large():
    assert fib(20) == [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181]