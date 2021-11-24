from count import count_char

def test_empty():
    assert count_char("") == {}

def test_simple():
    assert count_char("abc") == {"a": 1, "b": 1, "c": 1}

def test_double():
    assert count_char("aa") == {"a": 2}

def test_complex():
    assert count_char("asdadasdasdddsasdadZEAL")\
        == {'a': 6, 's': 5, 'd': 8, 'Z': 1, 'E': 1, 'A': 1, 'L': 1}

def test_single():
    assert count_char("AAAAAAAAAA") == {'A': 10}
