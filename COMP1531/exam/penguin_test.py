from penguin import validate

def test_1():
    assert validate('P8464Q94944Z')

def test_2():
    assert validate('A1234B12344C')

def test_3():
    assert not validate('A1234567890B')

def test_4():
    assert validate('A1234G67890Z')

def test_5():
    assert not validate('3')

def test_6():
    assert not validate('Z1234B12344A')

def test_7():
    assert not validate('A1234B12344A')

def test_8():
    assert not validate('A1111B11111C')

def test_9():
    assert not validate('A1234B12355C')
