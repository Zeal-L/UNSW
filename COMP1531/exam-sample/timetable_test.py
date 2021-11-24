from timetable import timetable
from datetime import date, time, datetime


def test_documentation():
    assert timetable([date(2019, 9, 27), date(2019, 9, 30)], [time(14, 10), time(10, 30)]) \
        == [datetime(2019, 9, 27, 10, 30), datetime(2019, 9, 27, 14, 10),
            datetime(2019, 9, 30, 10, 30), datetime(2019, 9, 30, 14, 10)]


def test_no_times():
    assert timetable([date(2020, 9, 2)], []) == []
    assert timetable([date(2020, 1, 2), date(2019, 3, 1)], []) == []


def test_no_dates():
    assert timetable([], [time(2, 30), time(14, 20)]) == []
    assert timetable([], [time(13, 30)]) == []


def test_one_each():
    assert timetable([date(2019, 10, 10)], [time(11, 20)]) == [
        datetime(2019, 10, 10, 11, 20)]
    assert timetable([datetime(2020, 2, 28)], [time(1, 3)]) == [
        datetime(2020, 2, 28, 1, 3)]


def test_single_combination():
    assert timetable([date(2000, 1, 1)], [time(0, 0)]) == [
        datetime(2000, 1, 1, 0, 0)]


def test_many_dates():
    assert timetable([date(2000, 1, 1), date(2000, 1, 2), date(2000, 1, 3), date(2000, 1, 4)], [time(0, 0)]) == [
        datetime(2000, 1, 1, 0, 0), datetime(2000, 1, 2, 0, 0), datetime(2000, 1, 3, 0, 0), datetime(2000, 1, 4, 0, 0)]


def test_many_times():
    assert timetable([date(2000, 1, 1)], [time(0, 1), time(0, 2), time(0, 3), time(0, 4)]) == [datetime(
        2000, 1, 1, 0, 1), datetime(2000, 1, 1, 0, 2), datetime(2000, 1, 1, 0, 3), datetime(2000, 1, 1, 0, 4)]
