from unmasked import similarities

def test_documentation():
    assert similarities(['texts/austen.txt', 'texts/shakespeare.txt'], 'texts/unknown.txt') == [(0.629, 'texts/shakespeare.txt'), (0.599, 'texts/austen.txt')]

def test_identical():
    assert similarities(['texts/austen.txt'], 'texts/austen.txt') == [(1.0, 'texts/austen.txt')]

def test_similar():
    assert similarities(['texts/freewill.txt', 'texts/lobby.txt', 'texts/frivolity.txt'], 'texts/freewilldraft.txt') == [(1.0, 'texts/freewill.txt'), (0.996, 'texts/lobby.txt'), (0.963, 'texts/frivolity.txt')]

def test_dissimilar():
    assert similarities(['texts/speech.txt'], 'texts/unknown.txt') == [(0.534, 'texts/speech.txt')]

def test_nearempty():
    assert similarities(['texts/freewill.txt', 'texts/austen.txt', 'texts/speech.txt'], 'texts/nearlyempty.txt') == [(0.332, 'texts/speech.txt'), (0.298, 'texts/freewill.txt'), (0.0, 'texts/austen.txt')]

def test_punctuation():
    assert similarities(['texts/unsw.txt'], 'texts/punctuation.txt') == [(0.761, 'texts/unsw.txt')]
