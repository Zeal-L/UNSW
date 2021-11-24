from lightup import get_board_state

def test_documentation_happy():
  # Example board, happy state.
  assert (get_board_state('''
...1.0.
X......
..X.X..
X...L.X
..X.3..
.L....X
L3L2...'''.strip().split('\n'))) == 'happy'

def test_documentation_solved():
  # Example board, solved state.
  assert (get_board_state('''
..L1.0.
X...L..
L.X.X.L
X...L.X
..XL3L.
.L....X
L3L2L..'''.strip().split('\n'))) == 'solved'

def test_documentation_unhappy():
  # Example board, unhappy state.
  assert (get_board_state('''
L..1L0.
X.L....
L.X.X.L
X...L.X
..XL3L.
.L....X
L3L2L..'''.strip().split('\n'))) == 'unhappy'

def test_documentation_happy2():
  # Different board, happy state.
  assert(get_board_state('''
L1.L.
..L3L
..X1.
.1...
.....'''.strip().split('\n'))) == 'happy'

def test_1x1_white():
    assert get_board_state('''.'''.strip().split('\n')) == 'happy'

def test_1x1_black():
    assert get_board_state('''X'''.strip().split('\n')) == 'solved'

def test_1x1_lamp():
    assert get_board_state('''L'''.strip().split('\n')) == 'solved'

def test_1x1_numbered_solved():
    assert get_board_state('''0'''.strip().split('\n')) == 'solved'

def test_1x1_numbered_unsolved():
    assert get_board_state('''1'''.strip().split('\n')) == 'happy'

def test_3x3_diagonal():
    assert get_board_state('''
L..
...
..L
    '''.strip().split('\n')) == 'happy'

def test_3x3_onelamp():
    assert get_board_state('''
L..
...
...
'''.strip().split('\n')) == 'happy'

def test_3x3_twolamps():
    assert get_board_state('''
L..
...
L..
'''.strip().split('\n')) == 'unhappy'

def test_3x3_solved():
    assert get_board_state('''
L..
.X.
..L
'''.strip().split('\n')) == 'solved'

def test_3x3_number_happy():
    assert get_board_state('''
2L.
..X
L..
'''.strip().split('\n')) == 'happy'

def test_3x3_number_solved():
    assert get_board_state('''
1L.
..X
L..
'''.strip().split('\n')) == 'solved'

def test_9x9_happy():
    assert get_board_state('''.....X...
XXL..X.XX
L....X.XX
.XX1XX...
.X.X...X.
.X.X.3.X.
...2LXL..
.X.L.XX1.
.........'''.strip().split('\n')) == 'happy'

def test_9x9_solved():
    assert get_board_state('''
L....X..L
XXL..X.XX
...L.X.XX
.XX1XX.L.
.X.X.L.X.
.X.XL3LX.
..L2.X.X.
.X.L.XX1L
L........'''.strip().split('\n')) == 'solved'

def test_9x9_unhappy():
    assert get_board_state('''.....X...
XXL..X.XX
L....X.XX
.XX1XX...
.X.X...X.
.X.X.3.X.
...2LXL..
.X.L.XX1.
L........'''.strip().split('\n')) == 'unhappy'
