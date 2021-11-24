from circle import Circle
import pytest

def test_small():
    c = Circle(3)
    assert(round(c.circumference(), 1) == 18.8)
    assert(round(c.area(), 1) == 28.3)

def test_big():
    c = Circle(25)
    assert(round(c.circumference(), 1) == 157.1)
    assert(round(c.area(), 1) == 1963.5)

def test_zero():
    c = Circle(0)
    assert(round(c.circumference(), 1) == 0)
    assert(round(c.area(), 1) == 0)

def test_negative():
    with pytest.raises(ValueError):
        c = Circle(-1)
        assert c.circumference()
        assert c.area()
