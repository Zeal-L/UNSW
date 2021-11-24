def transpose(matrix):
    '''
    Given a matrix, calculate its transpose. Transposing a matrix swaps its rows
    with its columns, so the element at position (i,j) of the matrix is now at
    position (j,i).

    Params:
        matrix (list): A matrix represented as a list of lists, where each inner
        list is of the same length.

    Returns:
        (list): The transposed matrix, represented as a lists of lists where
        each inner list is the same length.

    Raises:
        ValueError: If the inner lists of the argument are not all of the same
        length.
    '''
    if matrix == [[]]:
        return matrix

    result = list(map(list, zip(*matrix)))
    if sum(list(map(len, result))) != sum(list(map(len, matrix))):
        raise ValueError('Inner lists of matrix are not all of the same length.')

    return result

