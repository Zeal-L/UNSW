def magic(square):
    target_sum = sum(square[0])

    for row in square:
        if row.count(row[0]) == len(square) or len(row) != len(square):
            return "Invalid data: missing or repeated number"

        row_sum = 0
        for col in row:
            row_sum += col
        if row_sum != target_sum:
            return "Not a magic square"

    for col in range(len(square)):
        col_sum = 0
        for row in range(len(square)):
            col_sum += square[row][col]
        if col_sum != target_sum:
            return "Not a magic square"

    return "Magic square"



