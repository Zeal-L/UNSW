import re
from datetime import datetime, timedelta

def adjust(weeks, hours, string):
    if abs(weeks) > 50 or abs(hours) > 50:
        raise ValueError("Invalid number of weeks or hours")
    dt = datetime.strptime(string, '%H:%M on %d %B %Y')
    dt += timedelta(weeks=weeks, hours=hours)

    return dt.strftime('%H:%M on %d %B %Y')
