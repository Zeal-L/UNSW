from roman import roman

def test_basic():
    assert(roman("II")) == 2
    assert(roman("IV")) == 4
    assert(roman("IX")) == 9
    assert(roman("XIX")) == 19
    assert(roman("XX")) == 20

def test_large():
    assert(roman("MDCCLXXVI")) == 1776
    assert(roman("MMXIX")) == 2019