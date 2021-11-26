from frequency import frequency_get

def test_1():
    inputstr = """ I like you
    I really, really, like you!
    Yes I really do
    """

    outputstr = """I: 3
REALLY: 3
LIKE: 2
YOU: 2
YES: 1
DO: 1"""

    assert(frequency_get(inputstr) == outputstr)

def test_2():
    inputstr = """ I like you
    """

    outputstr = """I: 1
LIKE: 1
YOU: 1"""

    assert(frequency_get(inputstr) == outputstr)
