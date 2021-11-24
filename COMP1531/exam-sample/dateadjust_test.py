from dateadjust import adjust

import pytest

def test_1():
    assert adjust(4, 4, '16:40 on 28 January 2021') == '20:40 on 25 February 2021'

def test_feb():
    assert adjust(2, 7, '12:37 on 15 February 2020') == '19:37 on 29 February 2020'

def test_negative():
    assert adjust(-1, -1, '16:40 on 28 January 2021') == '15:40 on 21 January 2021'

def test_positive_error_weeks():
    with pytest.raises(ValueError):
        adjust(60, 0, '16:40 on 28 January 2021')

def test_positive_error_hours():
    with pytest.raises(ValueError):
        adjust(0, 60, '16:40 on 28 January 2021')

def test_negative_error_weeks():
    with pytest.raises(ValueError):
        adjust(-60, 0, '16:40 on 28 January 2021')

def test_negative_error_hours():
    with pytest.raises(ValueError):
        adjust(0, -60, '16:40 on 28 January 2021')
