def validate(penguin_number):

    if len(penguin_number) != 12:
        return False

    if penguin_number[0] >= penguin_number[5]:
        return False

    if penguin_number[5] >= penguin_number[11]:
        return False

    if sum(int(i) if i.isnumeric() else 0 for i in penguin_number) % 2 != 0:
        return False

    if int(penguin_number[-2]) % 2 != 0:
        return False

    return True


