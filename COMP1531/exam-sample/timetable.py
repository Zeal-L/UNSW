from datetime import date, time, datetime

def timetable(dates, times):
    """
    Complete the function timetable(dates, times) where given a list of dates and list of times,
    generates and returns a list of datetimes. All possible combinations of date and time are
    contained within the result. The result is sorted in chronological order.
    """
    result = []
    for d in dates:
        for t in times:
            result.append(datetime(d.year, d.month, d.day, t.hour, t.minute))
    return sorted(result)
