import pytest
import requests
import json
from src import config
from src.helper import generate_jwt

INVALID_ID = -1
INVALID_TOKEN = generate_jwt(INVALID_ID, 0)

@pytest.fixture(scope='function')
def setup1():
    requests.delete(config.url + "clear/v1")
    requests.post(config.url + "auth/register/v2", json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password', 'name_first' : "Test User", 'name_last' : "1"})
    requests.post(config.url + "auth/register/v2", json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password', 'name_first' : "Test User", 'name_last' : "2"})
    
    login_response1 = requests.post(config.url + "auth/login/v2", json={'email' : "testuser1@gmail.com", 'password' : "testuser1password"})
    user1_token = login_response1.json()
    login_response2 = requests.post(config.url + "auth/login/v2", json={'email' : "testuser2@gmail.com", 'password' : "testuser2password"})
    user2_token = login_response2.json()

    print(user1_token['token'])
    return [user1_token['token'], user2_token['token']]

# Tests for channels/create/v1
def test_channel_create_single(setup1):
    response = requests.post(config.url + 'channels/create/v2', json={'token' : setup1[0], 'name' : "public_channel", 'is_public' : True})
    data = response.json()
    assert data  == {"channel_id": 0}

    resp_2 = requests.post(config.url + 'channels/create/v2', json={'token' : setup1[0], 'name' : "private_channel", 'is_public' : False})
    data_2 = resp_2.json()
    assert data_2 == {"channel_id": 1}

def test_channel_create_multiple_public(setup1):    
    current_id = 0
    for i in range(3):
        response = requests.post(config.url + 'channels/create/v2', json={'token' : setup1[0], 'name' : "public_channel_" + str(i), 'is_public' : True})
        data = response.json()
        assert data == {"channel_id": current_id}
        current_id += 1

def test_channel_create_multiple_private(setup1):
    current_id = 0
    for i in range(3):
        response = requests.post(config.url + 'channels/create/v2', json={'token' : setup1[0], 'name' : "private_channel_" + str(i), 'is_public' : True})
        data = response.json()
        assert data == {"channel_id": current_id}
        current_id += 1

def test_channel_create_multiple_mixed(setup1):
    current_id = 0
    for i in range(5):
        privacy = False
        if i % 2 == 0:
            privacy = True
        response = requests.post(config.url + 'channels/create/v2', json={'token' : setup1[0], 'name' : "private_channel_" + str(i), 'is_public' : privacy})
        data = response.json()
        assert data == {"channel_id" : current_id}
        current_id += 1

def test_channels_create_invalid_input(setup1):
    response = requests.post(config.url + 'channels/create/v2', json={'token' : setup1[0], 'name' : "", 'is_public' : True})
    assert(response.status_code == 400)
    response2 = requests.post(config.url + 'channels/create/v2', json={'token' : setup1[0], 'name' : "channelnamelongerthan20", 'is_public' : True})
    assert(response2.status_code == 400)

def test_channels_create_invalid_access(setup1):
    response = requests.post(config.url + 'channels/create/v2', json={'token' : INVALID_TOKEN, 'name' : "invalid_creation", 'is_public' : True})
    assert(response.status_code == 403)



# Tests for channels/listall/v2
def test_no_channels_la(setup1):
    response = requests.get(config.url + "channels/listall/v2", params={'token' : setup1[0]})
    data = response.json()
    assert data == {'channels' : []}

def test_one_public_channel_la(setup1):
    requests.post(config.url + "channels/create/v2", json={'token' : setup1[0], 'name' : "list_all", 'is_public' : True})

    list_response_1 = requests.get(config.url + "channels/listall/v2", params={'token' : setup1[0]})
    data_1 = list_response_1.json()
    assert data_1 == {'channels' : [
        {
            "channel_id" : 0,
            "name" : "list_all"
        }
    ]}

    list_response_2 = requests.get(config.url + "channels/listall/v2", params={'token' : setup1[1]})
    data_2 = list_response_2.json()
    assert data_2 == {'channels' : [
        {
            'channel_id' : 0,
            "name" : "list_all"
        }
    ]}

def test_one_private_channel_la(setup1):
    requests.post(config.url + "channels/create/v2", json={'token' : setup1[0], 'name' : "list_all", 'is_public' : False})
    
    list_response_1 = requests.get(config.url + "channels/listall/v2", params={'token' : setup1[0]})
    data_1 = list_response_1.json()
    assert data_1 == {'channels' : [
        {
            "channel_id" : 0,
            "name" : "list_all"
        }
    ]}

    list_response_2 = requests.get(config.url + "channels/listall/v2", params={'token' : setup1[1]})
    data_2 = list_response_2.json()
    assert data_2 == {'channels' : [
        {
            "channel_id" : 0,
            "name" : "list_all"
        }
    ]}

def test_multiple_public_channels_la(setup1):
    for i in range(3):
        requests.post(config.url + "channels/create/v2", json={'token' : setup1[0], 'name' : "list_all_" + str(i), 'is_public' : True})
    
    list_response_1 = requests.get(config.url + "channels/listall/v2", params={'token' : setup1[0]})
    data_1 = list_response_1.json()
    assert data_1 == {'channels' : [
        {
            "channel_id" : 0,
            "name" : "list_all_0"
        },
        {
            "channel_id" : 1,
            "name" : "list_all_1"
        },
        {
            "channel_id" : 2,
            "name" : "list_all_2"
        },
    ]}

    list_response_2 = requests.get(config.url + "channels/listall/v2", params={'token' : setup1[1]})
    data_2 = list_response_2.json()
    assert data_2 == {'channels' : [
        {
            "channel_id" : 0,
            "name" : "list_all_0"
        },
        {
            "channel_id" : 1,
            "name" : "list_all_1"
        },
        {
            "channel_id" : 2,
            "name" : "list_all_2"
        }
    ]}

def test_multiple_private_channels_la(setup1):
    for i in range(3):
        requests.post(config.url + "channels/create/v2", json={'token' : setup1[0], 'name' : "list_all_" + str(i), 'is_public' : False})
    
    list_response_1 = requests.get(config.url + "channels/listall/v2", params={'token' : setup1[0]})
    data_1 = list_response_1.json()
    assert data_1 == {'channels' : [
        {
            "channel_id" : 0,
            "name" : "list_all_0"
        },
        {
            "channel_id" : 1,
            "name" : "list_all_1"
        },
        {
            "channel_id" : 2,
            "name" : "list_all_2"
        },
    ]}
    
    list_response_2 = requests.get(config.url + "channels/listall/v2", params={'token' : setup1[1]})
    data_2 = list_response_2.json()
    assert data_2 == { 'channels' : [
        {
            "channel_id" : 0,
            "name" : "list_all_0"
        },
        {
            "channel_id" : 1,
            "name" : "list_all_1"
        },
        {
            "channel_id" : 2,
            "name" : "list_all_2"
        }
    ]}

def test_invalid_token_la(setup1):
    response = requests.get(config.url + "channels/listall/v2", params={'token' : INVALID_TOKEN})
    assert response.status_code == 403

    
# Tests for channels/list/v2
def test_no_channels_l(setup1):
    list_response = requests.get(config.url + "channels/list/v2", params={'token' : setup1[0]})
    data = list_response.json()
    assert data == {'channels' : []}

    list_response = requests.get(config.url + "channels/list/v2", params={'token' : setup1[1]})
    data = list_response.json()
    assert data == {'channels' : []}

def test_one_public_channel_l(setup1):
    requests.post(config.url + "channels/create/v2", json={'token' : setup1[0], 'name' : "list_channel", 'is_public' : True})
    
    list_response_1 = requests.get(config.url  + "channels/list/v2", params={'token' : setup1[0]})
    data_1 = list_response_1.json()
    assert data_1 == {"channels" : [
        {
            "channel_id" : 0,
            "name" : "list_channel"
        }
    ]}

    list_response_2 = requests.get(config.url + "channels/list/v2", params={'token' : setup1[1]})
    data_2 = list_response_2.json()
    assert data_2 == {'channels' : []}

def test_one_private_channel_l(setup1):
    requests.post(config.url + "channels/create/v2", json={'token' : setup1[0], 'name' : "list_channel", 'is_public' : False})
    
    list_response_1 = requests.get(config.url  + "channels/list/v2", params={'token' : setup1[0]})
    data_1 = list_response_1.json()
    assert data_1 == {"channels" : [
        {
            "channel_id" : 0,
            "name" : "list_channel"
        }
    ]}

    list_response_2 = requests.get(config.url + "channels/list/v2", params={'token' : setup1[1]})
    data_2 = list_response_2.json()
    assert data_2 == {'channels' : []}
   
def test_multiple_public_channels_l(setup1):
    for i in range(3):
        requests.post(config.url + "channels/create/v2", json={'token' : setup1[0], 'name' : "list_channel_" + str(i), 'is_public' : True})
    list_response_1 = requests.get(config.url  + 'channels/list/v2', params={'token' : setup1[0]})
    
    data_1 = list_response_1.json()
    assert data_1 == {'channels' :[
        {
            "channel_id" : 0,
            "name" : "list_channel_0"
        },
        {
            "channel_id" : 1,
            "name" : "list_channel_1"
        },
        {
            "channel_id" : 2,
            "name" : "list_channel_2"
        }
    ]}

    list_response_2 = requests.get(config.url + 'channels/list/v2', params={'token' : setup1[1]})
    data_2 = list_response_2.json()
    assert data_2 == {'channels' : []}


def test_multiple_private_channels_l(setup1):
    for i in range(3):
        requests.post(config.url + "channels/create/v2", json={'token' : setup1[0], 'name' : "list_channel_" + str(i), 'is_public' : False})
    list_response_1 = requests.get(config.url  + 'channels/list/v2', params={'token' : setup1[0]})
    data_1 = list_response_1.json()
    assert data_1 == {'channels' :[
        {
            "channel_id" : 0,
            "name" : "list_channel_0"
        },
        {
            "channel_id" : 1,
            "name" : "list_channel_1"
        },
        {
            "channel_id" : 2,
            "name" : "list_channel_2"
        }
    ]}

    list_response_2 = requests.get(config.url + 'channels/list/v2', params={'token' : setup1[1]})
    data_2 = list_response_2.json()
    assert data_2 == {'channels' : []}
