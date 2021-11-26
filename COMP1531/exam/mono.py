def monotonic(lists):
    result = []
    for tuple in lists:
        if isinstance(tuple, int):
                raise ValueError("Tuple must contain at least two elements.")
        for i in range(len(tuple)):
            if abs(tuple[i]) >= 100000:
                raise ValueError("Absolute value of number must be less than 100000.")
        if all(tuple[i] <= tuple[i+1] for i in range(len(tuple)-1)):
            result.append("monotonically increasing")
        elif all(tuple[i] >= tuple[i+1] for i in range(len(tuple)-1)):
            result.append("monotonically decreasing")
        else:
            result.append("neither")
    return result



