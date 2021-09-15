import pytest
import sys
sys.path.append(r'C:\Users\Zeal\Desktop\COMP\COMP1531\Python')
import NOTES


def sum(x, y):
    return x + y

def test_sum_small():
    assert sum(1, 2) == 3, "1 + 2 == 3"

def test_sum_negative():
    assert sum(-1, 1) == 0

def test_sum_large():
    assert sum(654654654, 65456746874) == 66111401528

