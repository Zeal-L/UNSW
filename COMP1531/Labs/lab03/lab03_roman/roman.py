def roman(numerals):
    '''
    Given Roman numerals as a string, return their value as an integer. You may
    assume the Roman numerals are in the "standard" form, i.e. any digits
    involving 4 and 9 will always appear in the subtractive form.

    For example:
    >>> roman("II")
    2
    >>> roman("IV")
    4
    >>> roman("IX")
    9
    >>> roman("XIX")
    19
    >>> roman("XX")
    20
    >>> roman("MDCCLXXVI")
    1776
    >>> roman("MMXIX")
    2019
    '''

    sum = 0
    convert = {'M': 1000,'D': 500 ,'C': 100,'L': 50,'X': 10,'V': 5,'I': 1}
    for i in range(len(numerals) - 1):
        if convert[numerals[i]] < convert[numerals[i + 1]]:
            sum -= convert[numerals[i]]
        else:
            sum += convert[numerals[i]]
    sum += convert[numerals[-1]]
    return sum

print(roman("MMXIX"))
