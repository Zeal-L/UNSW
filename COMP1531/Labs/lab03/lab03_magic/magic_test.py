from magic import magic

def test_magic():
    assert magic([[8, 1, 6],
                  [3, 5, 7],
                  [4, 9, 2]]) == 'Magic square'
    assert magic([[2, 7, 6],
                  [9, 5, 1],
                  [4, 3, 8]]) == 'Magic square'

def test_invalid():
    assert magic([[1, 1, 1],
                  [1, 1, 1],
                  [1, 1, 1]]) == 'Invalid data: missing or repeated number'
    assert magic([[1, 2],
                  [3, 4, 5],
                  [6, 7, 8]]) == 'Invalid data: missing or repeated number'

def test_notmagic():
    assert magic([[1, 2, 3],
                  [4, 5, 6],
                  [7, 8, 9]]) == 'Not a magic square'
    assert magic([[1, 2, 3],
                  [1, 2, 3],
                  [1, 2, 3]]) == 'Not a magic square'

def test_4x4():
    assert magic([[116, 3, 2, 113],
                  [5, 110, 111, 8],
                  [9, 106, 107, 12],
                  [104, 15, 14, 101]]) == 'Magic square'
