from interleavings import interleavings

def test_documentation1():
    assert interleavings('ab', 'cd') == ['abcd', 'acbd', 'acdb', 'cabd', 'cadb', 'cdab']

def test_documentation2():
    assert interleavings('a', 'cd') == ['acd', 'cad', 'cda']

def test_single():
    assert interleavings('a', 'b') == ['ab', 'ba']

def test_uneven():
    assert interleavings('za','xy') == ['xyza', 'xzay', 'xzya', 'zaxy', 'zxay', 'zxya']

def test_uppercase():
    assert interleavings('A', 'BCDE') == ['ABCDE', 'BACDE', 'BCADE', 'BCDAE', 'BCDEA']

def test_empty():
    assert interleavings('','') == ['']
