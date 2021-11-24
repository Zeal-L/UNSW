def permutations(string):
    '''
    For the given string, compute the set of all permutations of the characters of that string. For example:
    >>> permutations('ABC')
    {'ABC', 'ACB', 'BAC', 'BCA', 'CAB', 'CBA'}

    Params:
      string (str): The string to permute

    Returns:
      (set of str): Each string in this set should be a permutation of the input string.
    '''

    return heap_permutation(list(string), len(string))

def heap_permutation(elems, size):
    if size == 1:
        return { ''.join(elems) }

    perms = set()
    for i in range(size):
        perms = perms.union(heap_permutation(elems, size - 1))

        if size % 2 == 1:
            elems[0], elems[size-1] = elems[size-1], elems[0]
        else:
            elems[i], elems[size-1] = elems[size-1], elems[i]
    return perms

