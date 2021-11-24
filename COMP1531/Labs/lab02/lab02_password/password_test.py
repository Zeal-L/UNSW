'''
Tests for check_password()
'''
from password import check_password

def test_strong():
    assert check_password("Abc123456789") == "Strong password"
    assert check_password("ahsHFS646480") == "Strong password"

def test_moderate():
    assert check_password("Abc12345") == "Moderate password"
    assert check_password("12268764645") == "Moderate password"

def test_poor():
    assert check_password("123") == "Poor password"
    assert check_password("abc") == "Poor password"
    assert check_password("AKJDHAKDHAASDD") == "Poor password"
    assert check_password("aaskjdhaksfhak") == "Poor password"

def test_horrible():
    assert check_password("password") == "Horrible password"
    assert check_password("iloveyou") == "Horrible password"
    assert check_password("123456") == "Horrible password"

def test_empty():
    assert check_password("") == "Poor password"
    assert check_password(" ") == "Poor password"
