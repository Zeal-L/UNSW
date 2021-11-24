def count_char(message):
    '''
    Counts the number of occurrences of each character in a string. The result should be a dictionary where the key is the character and the dictionary is its count.

    For example,
    >>> count_char("HelloOo!")
    {'H': 1, 'e': 1, 'l': 2, 'o': 2, 'O': 1, '!': 1}
    '''

    result = {}
    for i in message:
        if (result.get(i) == None):
            result[i] = 1
        else:
            result[i] = result[i] + 1
    return result
