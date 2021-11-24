from cipher import cipher

def test_documentation():
    assert cipher('zebras', 'we are discovered. flee at once.') == 'evlndacdtbeseaarofocdeecewiree'

def test_tomato():
    assert cipher('tomato', 'the quick brown fox jumped over the lazy dog') == 'qrxdhdeboetyhkfprziwuvlgtcnmeauojoeo'

def test_python():
    assert cipher('python', 'all my group members are really good at coding') == 'mpreoobgealdidymsaodcarmrlanluergcalobeytg'

def test_repeated():
    # Testing with repeated letters in the key
    assert cipher('mammamia', 'Here we go again') == 'egwnocgbHaraeiea'

def test_short():
    # Testing where the text is shorter than the key
    assert cipher('supercalafagialisticexpialadotious', 'Hello there') == 'hradoqtjrlkebcfinueepsvlmoHgxhtewl'

def test_veryshort():
    assert cipher('x', 'Update on unsws response to covid nineteen') == 'Updateonunswsresponsetocovidnineteen'

def test_empty():
    assert cipher('x', '') == ''
