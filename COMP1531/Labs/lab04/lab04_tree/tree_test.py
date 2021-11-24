from tree import draw

def test_documentation1():
    assert draw(("hello", (("a", ()), ("b", (("cde", ()), ("fg", ())))))) == '''[hello_____]
[a][b______]
...[cde][fg]'''

def test_documentation2():
    assert draw(("supercalifragilisticexpialidocious",(("a",(("b",(("candy",()),)),("onomatopoeia",()),)),("d",(("egg",(("f",()),)),)),))) == '''[supercalifragilisticexpialidocious]
[a__________________][d__]..........
[b____][onomatopoeia][egg]..........
[candy]..............[f]............'''

def test_singlenode():
    assert draw(('Kenobi',())) == '[Kenobi]'

def test_threetiers():
    assert draw(("hello", (("a", ()), ("b", (("fg", ()),))))) == '''[hello]
[a][b_]
...[fg]'''

def test_twotiers():
    assert draw(("hello", (("a", ()), ("weallhatecovidnineteen", ())))) == '''[hello____________________]
[a][weallhatecovidnineteen]'''

def test_pyramid():
    assert draw(("x", [("x", [('xxx', [('xxxx', [('xxxxx', [])])])])])) == '''[x____]
[x____]
[xxx__]
[xxxx_]
[xxxxx]'''

def test_pyramid_upsidedown():
    assert draw(("xxxxx", [("xxxx", [('xxx', [('xx', [('x', [])])])])])) == '''[xxxxx]
[xxxx].
[xxx]..
[xx]...
[x]....'''

def test_longbranch():
    assert draw(("x", [("x", [('dearmembersoftheunswcommunity', [('x', [('x', [])])])])])) == '''[x____________________________]
[x____________________________]
[dearmembersoftheunswcommunity]
[x]............................
[x]............................'''

def test_harder():
    assert draw(("1", [("2", [('4', [('7', [])]), ('5', [('8', [('10', [('12', []), ('13', [('14', [])])])]), ('9',[('11',[])])])])])) == '''[1____________]
[2____________]
[4][5_________]
[7][8_____][9_]
...[10____][11]
...[12][13]....
.......[14]....'''
