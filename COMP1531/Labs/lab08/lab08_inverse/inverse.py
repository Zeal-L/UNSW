def inverse(d):
    '''
    Given a dictionary d, invert its structure such that values in d map to lists of keys in d.
    For example:
    >>> inverse({1: 'A', 2: 'B', 3: 'A'})
    {'A': [1, 3], 'B': [2]}

    Params:
		d (dict): A dictionary where all the values are hashable (i.e. can be used as keys in the
		result).

    Returns:
        (dict): A dictionary with the structure described above.
    '''
    result = {}
    for key, value in d.items():
        if value not in result:
            result[value] = [key]
        else:
            result[value].append(key)
    return result
