import pytest
import requests
import json
from src import config
from tests.requests import *

##################################################
# clear_v1 Tests
##################################################

# Expect to work since clear should return nothing.
def test_clear():
    resp = requests.delete(config.url + 'clear/v1')
    assert json.loads(resp.text) == {}

# Expect fail since the data_store is cleared.
def test_login_after_clear():
    post_register('validemail@gmail.com', '123abc!@#', 'Zeal', 'Liang')
    requests.delete(config.url + 'clear/v1')
    assert post_login('validemail@gmail.com', '123abc!@#').status_code == INPUTERROR


