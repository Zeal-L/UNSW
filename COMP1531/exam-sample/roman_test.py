from roman import roman

def test_documentation():
    assert roman("II") == 2
    assert roman("IV") == 4
    assert roman("IX") == 9
    assert roman("XIX") == 19
    assert roman("XX") == 20
    assert roman("MDCCLXXVI") == 1776
    assert roman("MMXIX") == 2019

def test_single_characters():
    assert roman("I") == 1
    assert roman("V") == 5
    assert roman("X") == 10
    assert roman("L") == 50
    assert roman("C") == 100
    assert roman("M") == 1000

def test_up_to_ten():
    assert roman('I') == 1
    assert roman('III') == 3
    assert roman('V') == 5
    assert roman('VI') == 6
    assert roman('VII') == 7
    assert roman('VIII') == 8
    assert roman('X') == 10

def test_four_nine_numbers():
    assert roman('XLIX') == 49
    assert roman('XL') == 40
    assert roman('XCIX') == 99
    assert roman('XC') == 90
    assert roman('XCIV') == 94
    assert roman('CDXCIX') == 499
    assert roman('CMXCIX') == 999

def test_19():
    assert roman("XIX") == 19

def test_20():
    assert roman("XX") == 20

def test_1776():
    assert roman("MDCCLXXVI") == 1776

def test_2019():
    assert roman("MMXIX") == 2019

def test_3_in_row():
    assert roman("CXXX") == 130

def test_8():
    assert roman("VIII") == 8
