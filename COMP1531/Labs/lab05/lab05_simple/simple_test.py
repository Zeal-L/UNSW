import pytest
import requests

url = "http://localhost:5000/"

def post_name_add(name):
    resp = requests.post(url + '/name/add', json={
        'name' : name
    })
    return resp

def get_name():
    resp = requests.get(url + '/names')
    return resp

def post_name_remove(name):
    resp = requests.delete(url + '/name/remove', json={
        'name' : name
    })
    return resp

def post_name_clear():
    resp = requests.delete(url + '/name/clear')
    return resp


@pytest.fixture(scope="function")
def test_setup():
    post_name_clear()

def test_add_one_name(test_setup):
    post_name_add('Zeal')
    assert get_name().json() == { 'names' : [ 'Zeal'] }

def test_add_two_name(test_setup):
    post_name_add('Zeal')
    post_name_add('Kevin')
    assert get_name().json() == { 'names' : ['Zeal', 'Kevin'] }

def test_add_multiple_name_then_remove(test_setup):
    post_name_add('Asus')
    post_name_add('Acer')
    post_name_add('Dell')
    assert get_name().json() == { 'names': [ 'Asus', 'Acer', 'Dell' ]}
    post_name_remove('Dell')
    assert get_name().json() == { 'names': [ 'Asus', 'Acer' ]}