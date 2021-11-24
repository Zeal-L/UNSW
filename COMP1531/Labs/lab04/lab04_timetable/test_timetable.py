from timetable import *

def test_timetable():
    assert timetable([date(2019,9,27), date(2019,9,30)], [time(14,10), time(10,30)]) \
        == [datetime(2019,9,27,10,30), datetime(2019,9,27,14,10), datetime(2019,9,30,10,30), datetime(2019,9,30,14,10)]

def test_timetable_2():
    assert timetable([date(2019,2,28), date(2019,9,30)], [time(14,10), time(10,30)]) \
        == [datetime(2019,2,28,10,30), datetime(2019,2,28,14,10), datetime(2019,9,30,10,30), datetime(2019,9,30,14,10)]
