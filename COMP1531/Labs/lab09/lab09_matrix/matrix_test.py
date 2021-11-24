import pytest
from matrix import Matrix


def test_documentation():
    # Test new
    m1 = Matrix(2, 2)
    m1.set((0, 0), 7)
    m1.set((0, 1), 2)
    m1.set((1, 0), 3)

    assert str(m1) == '7 2\n3 0'

    # Testing adding a scalar
    m2 = m1.add(3)
    assert str(m2) == '10 5\n6 3'

    m3 = Matrix(2, 2)
    m3.set((0, 0), 1)
    m3.set((0, 1), 3)
    m3.set((1, 0), 4)
    m3.set((1, 1), 5)
    assert str(m3) == '1 3\n4 5'

    # Testing adding matrices
    m4 = m1.add(m3)
    assert str(m4) == '8 5\n7 5'

    # Test multiply
    m5 = m1.mul(3)
    assert str(m5) == '21 6\n9 0'

    m6 = m1.mul(m3)
    assert str(m6) == '15 31\n3 9'


def test_zero():
    m = Matrix(0, 0)
    with pytest.raises(IndexError):
        m.get((0, 0))


def test_zero_add():
    # Testing addition of a zero matrix
    m = Matrix(0, 0)
    m1 = m.add(1)
    with pytest.raises(IndexError):
        m.get((0, 0))


def test_zero_multiply():
    m = Matrix(0, 0)
    m1 = m.mul(1)
    with pytest.raises(IndexError):
        m.get((0, 0))


def test_2x2_identity():
    m = Matrix(2, 2)
    m.set((0, 0), 1)
    m.set((1, 1), 1)
    assert str(m) == '1 0\n0 1'


def test_get_indexerror():
    m1 = Matrix(2, 2)
    with pytest.raises(IndexError) as _:
        m1.get((-1, 0))

    with pytest.raises(IndexError) as _:
        m1.get((2, 1))


def test_set_indexerror():
    m1 = Matrix(2, 2)
    with pytest.raises(IndexError) as _:
        m1.set((-1, 0), 1)

    with pytest.raises(IndexError) as _:
        m1.set((2, 1), 1)


def test_add_typerror():
    m1 = Matrix(2, 2)
    with pytest.raises(TypeError):
        m1.add('2')


def test_mul_valueerror():
    m1 = Matrix(2, 2)
    m8 = Matrix(3, 4)
    with pytest.raises(ValueError):
        m1.mul(m8)


def test_add_valueerror():
    m1 = Matrix(2, 2)
    m8 = Matrix(3, 4)
    with pytest.raises(ValueError):
        m1.add(m8)


def test_set_typeerror():
    m1 = Matrix(1, 1)

    with pytest.raises(TypeError):
        m1.set((0, 0), 'hello')


def test_mul_typeerror():
    m1 = Matrix(1, 1)

    with pytest.raises(TypeError):
        m1.mul('a')


def test_multiply_4x2():
    m7 = Matrix(2, 3)
    m7.set((0, 0), 2)
    m7.set((0, 1), 1)
    m7.set((0, 2), 4)
    m7.set((1, 0), 0)
    m7.set((1, 1), 1)
    m7.set((1, 2), 1)

    m8 = Matrix(3, 4)
    m8.set((0, 0), 6)
    m8.set((0, 1), 3)
    m8.set((0, 2), -1)
    m8.set((1, 0), 1)
    m8.set((1, 1), 1)
    m8.set((1, 3), 4)
    m8.set((2, 0), -2)
    m8.set((2, 1), 5)
    m8.set((2, 3), 2)

    print(m7)
    print()
    print(m8)
    m9 = m7.mul(m8)
    assert str(m9) == '5 27 -2 12\n-1 6 0 6'
