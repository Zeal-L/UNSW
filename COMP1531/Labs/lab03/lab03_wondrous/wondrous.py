def wondrous(start):
    '''
    Returns the wondrous sequence for a given number.
    '''
    current = start
    sequence = []
    sequence.append(start)

    while current != 1 and current != 0:
        if (current % 2 == 0):
            current = int(current / 2)
        else:
            current = (current * 3) + 1
        sequence.append(current)

    return sequence

print(wondrous(100))
