# Imports
import pytest
import requests
import json
from datetime import datetime
from random import randint, choice
from string import ascii_letters
from hypothesis import given, strategies, Verbosity, settings
from src import config
from src.helper import generate_jwt

# Constants
INVALID_ID = -1
INVALID_SESSION = -1
INVALID_TOKEN = generate_jwt(INVALID_ID, INVALID_SESSION)
ACCESS_ERROR = 403
INPUT_ERROR = 400
SUCCESS = 200
MESSAGE = "Hello World!"

# Setup Functions

# MAKE THE OTHER USERS JOIN THE CHANNEL
@pytest.fixture(scope='function')
def channel_setup():
    requests.delete(config.url + "clear/v1")
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password', 'name_first' : "Test User", 'name_last' : "1"})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password', 'name_first' : "Test User", 'name_last' : "2"})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password', 'name_first' : "Test User", 'name_last' : "3"})

    login1_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password'})
    login1_token = login1_response.json()
    login2_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password'})
    login2_token = login2_response.json()
    login3_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password'})
    login3_token = login3_response.json()

    channel_response = requests.post(config.url + "channels/create/v2", json={'token' : login1_token['token'], 'name' : 'Test Channel 1', 'is_public' : True})
    channel_id = channel_response.json()

    requests.post(config.url + 'channel/join/v2', json={'token' : login2_token['token'], 'channel_id' : channel_id['channel_id']})
    requests.post(config.url + 'channel/join/v2', json={'token' : login3_token['token'], 'channel_id' : channel_id['channel_id']})

    return [login1_token['token'], channel_id['channel_id']]

@pytest.fixture(scope='function')
def dm_setup():
    requests.delete(config.url + "clear/v1")
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password', 'name_first' : "Test User", 'name_last' : "1"})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password', 'name_first' : "Test User", 'name_last' : "2"})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password', 'name_first' : "Test User", 'name_last' : "3"})
    login_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password'})
    login_token = login_response.json()

    dm_response = requests.post(config.url + "dm/create/v1", json={'token' : login_token['token'], 'u_ids' : [2,3]})
    dm_id = dm_response.json()
    return [login_token['token'], dm_id['dm_id']]

@pytest.fixture(scope='function')
def dm_channel_setup():
    requests.delete(config.url + "clear/v1")
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password', 'name_first' : "Test User", 'name_last' : "1"})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password', 'name_first' : "Test User", 'name_last' : "2"})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password', 'name_first' : "Test User", 'name_last' : "3"})
    
    login_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password'})
    login_token = login_response.json()
    login2_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password'})
    login2_token = login2_response.json()
    login3_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password'})
    login3_token = login3_response.json()

    channel_response = requests.post(config.url + "channels/create/v2", json={'token' : login_token['token'], 'name' : 'Test Channel', 'is_public' : True})
    channel_id = channel_response.json()

    requests.post(config.url + 'channel/join/v2', json={'token' : login2_token['token'], 'channel_id' : channel_id['channel_id']})
    requests.post(config.url + 'channel/join/v2', json={'token' : login3_token['token'], 'channel_id' : channel_id['channel_id']})
    
    dm_response = requests.post(config.url + "dm/create/v1", json={'token' : login_token['token'], 'u_ids' : [2,3]})
    dm_id = dm_response.json()
    
    return [login_token['token'], login2_token['token'], login3_token['token'], channel_id['channel_id'], dm_id['dm_id']]

# Tests
def test_invalid_token(channel_setup):
    search_response = requests.get(config.url + 'search/v1', params={'token' : INVALID_TOKEN, 'query_str' : MESSAGE})
    assert search_response.status_code == ACCESS_ERROR

def test_invalid_query_over(channel_setup):
    # generate a bunch of messages and send them
    for i in range(20):
        length = randint(1,1000)
        message = 'a' * length
        message_response = requests.post(config.url + 'message/send/v1', json={'token' : channel_setup[0], 'channel_id' : channel_setup[1], 'message' : message})
        message_id = message_response.json()
        assert message_id == {'message_id' : i}
        query = 'a' * 1001
        print(len(query))
        search_response = requests.get(config.url + 'search/v1', params={'token' : channel_setup[0], 'query_str' : query})
        assert search_response.status_code == INPUT_ERROR

def test_invalid_query_under(channel_setup):
    for i in range(100):
        length = randint(1,1000)
        message = 'a' * length
        message_response = requests.post(config.url + 'message/send/v1', json={'token' : channel_setup[0], 'channel_id' : channel_setup[1], 'message' : message})
        message_id = message_response.json()
        assert message_id == {'message_id' : i}    

    serach_response = requests.get(config.url + 'search/v1', params={'token' : channel_setup[0], 'query_str' : ''})
    assert serach_response.status_code == INPUT_ERROR


def test_no_channels_no_dms(dm_channel_setup):
    # Make a user that is not associated with any channels or dms
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser4@gmail.com', 'password' : 'testuser4password', 'name_first' : "Test User", 'name_last' : "4"})
    login_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser4@gmail.com', 'password' : 'testuser4password'})
    token = login_response.json()['token']

    search_response = requests.get(config.url + 'search/v1', params={'token' : token, 'query_str' : MESSAGE})
    search_results = search_response.json()
    assert search_results == {'messages' : []}

def test_no_messages(dm_channel_setup):
    # query for a user that has sent no messages
        search_response = requests.get(config.url + 'search/v1', params={'token' : dm_channel_setup[2], 'query_str' : MESSAGE})
        search_result = search_response.json()
        assert search_result == {'messages' : []}


def test_search_channel_single(channel_setup):
    message_response = requests.post(config.url + 'message/send/v1', json={'token' : channel_setup[0], 'channel_id' : channel_setup[1], 'message' : MESSAGE})
    assert message_response.status_code == SUCCESS
    time = datetime.now().strftime('%d/%m/%Y, %H:%M:%S')
    queries = [MESSAGE, MESSAGE[-10: ], MESSAGE[ :10], MESSAGE[0]]
    for query in queries:
        search_response = requests.get(config.url + 'search/v1', params={'token' : channel_setup[0], 'query_str' : query})
        search_results = search_response.json()
        assert search_results == {'messages': [
                {
                    'message_id' : 0,
                    'u_id' : 1,
                    'message' : MESSAGE,
                    'time_created' : time,
                    'reacts' : [],
                    'is_pinned' : False
                }
            ]
        }

def test_search_dm_single(dm_setup):
    dm_response = requests.post(config.url + 'message/senddm/v1', json={'token' : dm_setup[0], 'dm_id' : dm_setup[1], 'message' : MESSAGE})
    assert dm_response.status_code == SUCCESS
    time = datetime.now().strftime('%d/%m/%Y, %H:%M:%S')
    queries = [MESSAGE, MESSAGE[-10: ], MESSAGE[ :10], MESSAGE[0]]
    for query in queries:
        search_response = requests.get(config.url + 'search/v1', params={'token' : dm_setup[0], 'query_str' : query})
        search_results = search_response.json()
        assert search_results == {'messages': [
                {
                    'message_id' : 0,
                    'u_id' : 1,
                    'message' : MESSAGE,
                    'time_created' : time,
                    'reacts' : [],
                    'is_pinned' : False
                }
            ]
        }

def test_search_channel_multiple(dm_channel_setup):
    tokens = dm_channel_setup[ :3] # all users
    messages = []
    for i in range(10):
        u_id = randint(0,2)
        message_response = requests.post(config.url + 'message/send/v1', json={'token' : dm_channel_setup[u_id], 'channel_id' : dm_channel_setup[-2], 'message' : MESSAGE + ' ' + str(i)})
        time = datetime.now().strftime('%d/%m/%Y, %H:%M:%S')
        assert message_response.status_code == SUCCESS
        messages.append(
            {
                'message_id' : i,
                'u_id' : u_id + 1,
                'message' : MESSAGE + ' ' + str(i),
                'time_created' : time,
                'reacts' : [],
                'is_pinned' : False                
            }
        )
    queries = [MESSAGE, MESSAGE[randint(0, len(MESSAGE)/2): ], MESSAGE[ :randint(0, len(MESSAGE)/2)]]
    for query in queries:
        search_response = requests.get(config.url + 'search/v1', params={'token' : dm_channel_setup[randint(0,2)], 'query_str' : query})
        results = search_response.json()
        assert results == {'messages' : messages}

    for token in tokens: 
        search_response = requests.get(config.url + 'search/v1', params={'token' : token, 'query_str' : 'Testing'})
        results = search_response.json()
        assert results == {'messages' : []}

# def test_search_dm_multilpe(dm_channel_setup):
#     tokens = dm_channel_setup[ :3] # all users
#     messages = []
#     for i in range(10):
#         u_id = randint(0,2)
#         dm_response = requests.post(config.url + 'message/senddm/v1', json={'token' : dm_channel_setup[u_id], 'dm_id' : dm_channel_setup[-1], 'message' : MESSAGE + ' ' + str(i)})
#         time = datetime.now().strftime('%d/%m/%Y, %H:%M:%S')
#         assert dm_response.status_code == SUCCESS
#         messages.append(
#             {
#                 'message_id' : i,
#                 'u_id' : u_id + 1,
#                 'message' : MESSAGE + ' ' + str(i),
#                 'time_created' : time,
#                 'reacts' : [],
#                 'is_pinned' : False                
#             }
#         )
#     queries = [MESSAGE, MESSAGE[randint(0, len(MESSAGE)/2): ], MESSAGE[ :randint(0, len(MESSAGE)/2)]]
#     for query in queries:
#         search_response = requests.get(config.url + 'search/v1', params={'token' : dm_channel_setup[randint(0,2)], 'query_str' : query})
#         results = search_response.json()
#         assert results == {'messages' : messages}

#     for token in tokens: 
#         search_response = requests.get(config.url + 'search/v1', params={'token' : token, 'query_str' : 'Testing'})
#         results = search_response.json()
#         assert results == {'messages' : []}


def test_search_dm_and_channel(dm_channel_setup):
    tokens = dm_channel_setup[ :3] # all users
    messages = []

    for i in range(10):
        u_id = randint(0,2)
        message_response = requests.post(config.url + 'message/send/v1', json={'token' : dm_channel_setup[u_id], 'channel_id' : dm_channel_setup[-2], 'message' : MESSAGE + ' ' + str(i)})
        time = datetime.now().strftime('%d/%m/%Y, %H:%M:%S')
        assert message_response.status_code == SUCCESS
        messages.append(
            {
                'message_id' : i,
                'u_id' : u_id + 1,
                'message' : MESSAGE + ' ' + str(i),
                'time_created' : time,
                'reacts' : [],
                'is_pinned' : False                
            }
        )

    for i in range(10):
        u_id = randint(0,2)
        dm_response = requests.post(config.url + 'message/senddm/v1', json={'token' : dm_channel_setup[u_id], 'dm_id' : dm_channel_setup[-1], 'message' : MESSAGE + ' ' + str(i)})
        time = datetime.now().strftime('%d/%m/%Y, %H:%M:%S')
        assert dm_response.status_code == SUCCESS
        messages.append(
            {
                'message_id' : i + 10,
                'u_id' : u_id + 1,
                'message' : MESSAGE + ' ' + str(i),
                'time_created' : time,
                'reacts' : [],
                'is_pinned' : False                
            }
        )
    queries = [MESSAGE, MESSAGE[randint(0, len(MESSAGE)/2): ], MESSAGE[ :randint(0, len(MESSAGE)/2)]]
    for query in queries:
        search_response = requests.get(config.url + 'search/v1', params={'token' : dm_channel_setup[randint(0,2)], 'query_str' : query})
        results = search_response.json()
        assert results == {'messages' : messages}

    for token in tokens: 
        search_response = requests.get(config.url + 'search/v1', params={'token' : token, 'query_str' : 'Testing'})
        results = search_response.json()
        assert results == {'messages' : []}