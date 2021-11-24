import pytest
from matrix import Matrix


def test_wk4_documentation():
    # Test new
    m1 = Matrix(2, 2)
    m1[0, 0] = 7  # m1.set((0,0), 7)
    m1[0, 1] = 2  # m1.set((0,1), 2)
    m1[1, 0] = 3  # m1.set((1,0), 3)

    assert str(m1) == '7 2\n3 0'

    # Testing adding a scalar
    m2 = m1 + 3
    assert str(m2) == '10 5\n6 3'

    m3 = Matrix(2, 2)
    m3[0, 0] = 1
    m3[0, 1] = 3
    m3[1, 0] = 4
    m3[1, 1] = 5
    assert str(m3) == '1 3\n4 5'

    # Testing adding matrices
    m4 = m1 + m3
    assert str(m4) == '8 5\n7 5'

    # Test multiply
    m5 = m1 * 3
    assert str(m5) == '21 6\n9 0'

    m6 = m1 * m3
    assert str(m6) == '15 31\n3 9'


def test_ellipsis_col():
    m1 = Matrix(2, 2)
    m1[0, 0] = 7
    m1[0, 1] = 2
    m1[1, 0] = 3

    m1[..., 0] = (1, 1)
    assert m1[..., 0] == [1, 1]
    assert str(m1) == '1 2\n1 0'


def test_ellipsis_row():
    m = Matrix(2, 3)
    m[0, ...] = [1, 5, 9]
    assert m[0, ...] == [1, 5, 9]
    assert str(m) == '1 5 9\n0 0 0'


def test_ellipsis_exception_length():
    m = Matrix(2, 2)
    with pytest.raises(ValueError):
        m[..., 0] = (1, 2, 3)


def test_ellipsis_exception_double():
    m = Matrix(2, 2)
    with pytest.raises(TypeError):
        m[..., ...]

    with pytest.raises(TypeError):
        m[..., ...] = (1, 2)


def test_ellipsis_exception_type():
    m = Matrix(2, 2)
    with pytest.raises(TypeError):
        m[0, ...] = [1, 'a']

    with pytest.raises(TypeError):
        m[..., 0] = ['b', 2]


def test_zero():
    m = Matrix(0, 0)
    with pytest.raises(IndexError):
        m[0, 0]


def test_zero_add():
    # Testing addition of a zero matrix
    m = Matrix(0, 0)
    m1 = m + 1
    with pytest.raises(IndexError):
        m[0, 0]


def test_zero_multiply():
    m = Matrix(0, 0)
    m1 = m * 1
    with pytest.raises(IndexError):
        m[0, 0]


def test_2x2_identity():
    m = Matrix(2, 2)
    m[0, 0] = 1
    m[1, 1] = 1
    assert str(m) == '1 0\n0 1'


def test_get_indexerror():
    m1 = Matrix(2, 2)
    with pytest.raises(IndexError) as _:
        m1[-1, 0]

    with pytest.raises(IndexError) as _:
        m1[2, 1]


def test_set_indexerror():
    m1 = Matrix(2, 2)
    with pytest.raises(IndexError) as _:
        m1[-1, 0] = 1

    with pytest.raises(IndexError) as _:
        m1[2, 1] = 1


def test_add_typerror():
    m1 = Matrix(2, 2)
    with pytest.raises(TypeError):
        m1 + '2'


def test_mul_valueerror():
    m1 = Matrix(2, 2)
    m8 = Matrix(3, 4)
    with pytest.raises(ValueError):
        m1 * m8


def test_add_valueerror():
    m1 = Matrix(2, 2)
    m8 = Matrix(3, 4)
    with pytest.raises(ValueError):
        m1 + m8


def test_set_typeerror():
    m1 = Matrix(1, 1)

    with pytest.raises(TypeError):
        m1[0, 0] = 'hello'


def test_mul_typeerror():
    m1 = Matrix(1, 1)

    with pytest.raises(TypeError):
        m1 * 'a'


def test_multiply_4x2():
    m7 = Matrix(2, 3)
    m7[0, 0] = 2
    m7[0, 1] = 1
    m7[0, 2] = 4
    m7[1, 0] = 0
    m7[1, 1] = 1
    m7[1, 2] = 1

    m8 = Matrix(3, 4)
    m8[0, 0] = 6
    m8[0, 1] = 3
    m8[0, 2] = -1
    m8[1, 0] = 1
    m8[1, 1] = 1
    m8[1, 3] = 4
    m8[2, 0] = -2
    m8[2, 1] = 5
    m8[2, 3] = 2

    m9 = m7 * m8
    assert str(m9) == '5 27 -2 12\n-1 6 0 6'


def test_transpose():
    m10 = Matrix(5, 1)
    m10[0, 0] = 1
    m10[1, 0] = 2
    m10[2, 0] = 3
    m10[3, 0] = 4
    m10[4, 0] = 5
    m11 = m10.transpose()

    assert str(m11) == '1 2 3 4 5'


def test_copy():
    m10 = Matrix(5, 1)
    m10[0, 0] = 1
    m10[1, 0] = 2
    m10[2, 0] = 3
    m10[3, 0] = 4
    m10[4, 0] = 5
    m11 = m10.copy()
    m11[0, 0] = 0
    assert str(m11) == '0\n2\n3\n4\n5'
    assert str(m10) == '1\n2\n3\n4\n5'


def test_side_effects():
    m = Matrix(2, 2)
    m[0, 0] = 7
    m[0, 1] = 2
    m[1, 0] = 3
    m[1, 1] = 99
    cpy1 = m[1, ...]
    cpy2 = m[..., 1]

    cpy1[0] = 10
    cpy2[0] = 100
    assert cpy1 == [10, 99]
    assert cpy2 == [100, 99]

    assert str(m) == '7 2\n3 99'
