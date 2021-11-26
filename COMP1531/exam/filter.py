def filter_string(inp):
    if any(chr.isdigit() for chr in inp):
        raise ValueError("Input contains digits")
    result = ""
    for index, i in enumerate(inp):
        if index == 0:
            result += i
        else:
            if i not in ",.'\";?!":
                result += i.lower()

    return result


