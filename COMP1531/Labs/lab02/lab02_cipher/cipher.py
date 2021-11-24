def cipher(key, message):
    if message == '':
        return message
    temp = []       # Temporary array
    table = []      # 2D array
    count = 0       # length of array
    for letter in message:              # Forming the cipher table from "message"
        if letter.isalpha():
            temp.append(letter)
            count += 1
            if count == len(key):       # Switch to the next line
                table.append(temp.copy())
                temp.clear()
                count = 0

    if temp != []:                      # Append The Last line
        table.append(temp.copy())

    letter = 'a'
    while len(table[-1]) != len(key):   # Fill the last line with consecutive
        table[-1].append(letter)        # lowercase letters, if it is not long enough
        letter = chr(ord(letter) + 1)

    list_key = list(key)
    result = ''                     # Read the results vertically from the table
    for i in range(len(key)):       # in the alphabetical order of "key"
        min_letter = list_key.index(min(list_key))
        for row in range(len(table)):
            letter = table[row][min_letter]
            result += letter
        list_key[min_letter] = '{'  # '{' = 123 which is greater then 'z' = 122

    return result