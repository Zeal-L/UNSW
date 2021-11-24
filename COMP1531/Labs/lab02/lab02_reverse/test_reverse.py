'''
Tests for reverse_words()
'''
from reverse import reverse_words

def test_example():
    assert reverse_words(["Hello World", "I am here"]) == ['World Hello', 'here am I']

def test_number():
    assert reverse_words(["12 34", "56 78"]) == ['34 12', '78 56']

def test_empty():
    assert reverse_words(["  ", "  "]) == ['  ', '  ']

def test_single():
    assert reverse_words(["h", "i"]) == ['h', 'i']

def test_many():
    assert reverse_words(["Hello World", "I am here", "HA Ha Ha"]) == ['World Hello', 'here am I', 'Ha Ha HA']

def test_complex():
    assert reverse_words(["Hello World 7  ", "I    9"]) == ['  7 World Hello', '9    I']
