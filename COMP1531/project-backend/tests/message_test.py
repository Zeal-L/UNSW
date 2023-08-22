###############################################################################
# Message_Implementation tests for COMP1531, Iteration 3. Written by Dev Chopra
# for W13A, group Beagle.
###############################################################################

#############################################
# Import(s)
#############################################

import pytest
import requests
import json
import time
from datetime import datetime
from hypothesis import given, strategies, Verbosity, settings


import string
from random import choice
from requests.models import cookiejar_from_dict
from src import config
from src.helper import decode_jwt, generate_jwt
from tests.requests import *

#############################################
# Constant(s)
#############################################

INVALID_ID = -1
INVALID_TOKEN = generate_jwt(INVALID_ID, 0)
NORMAL_MESSAGE = "I'm going to make him an offer he can't refuse."
THOUSAND_CHARACTER_MESSAGE = 'a' * 1001
NO_CHARACTER_MESSAGE = ""
MESSAGE = 'Hello World!'
ACCESSERROR = 403
INPUTERROR = 400
SUCCESS = 200
INVALID_REACT = -1
VALID_REACT = 1

#############################################
# Initial setup (Reset state of application)
#############################################

@pytest.fixture(scope="function")
def setup():
    requests.delete(config.url + 'clear/v1')
    # Register first user
    first_user = json.loads(post_register('validemail@gmail.com', '123abc!@#', 'Hayden', 'Everest').text)
    # Register second user
    second_user = json.loads(post_register('anotheremail@gmail.com', '123abc4534!@#', 'Michael', 'Jackson').text)
    # Register third user
    third_user = json.loads(post_register('bruh@gmail.com', '123abc4534!@#', 'Big', 'Man').text)
    # Create New Channel
    new_channel = json.loads(post_channels_create(first_user['token'], "channel", True).text)

    return {'first_user' : first_user, 'second_user' : second_user, 'new_channel' : new_channel, 'third_user': third_user}

@pytest.fixture(scope="function")
def setup_dm():
    requests.delete(config.url + 'clear/v1')
    # Register first user
    first_user = json.loads(post_register('general_kenobi@gmail.com', '123abc!@#', 'Obi Wan', 'Kenobi').text)
    # Register second user
    second_user = json.loads(post_register('anakin_skywalker@gmail.com', '123abc4534!@#', 'Anakin', 'Skywalker').text)
    # Register third user
    third_user = json.loads(post_register('yoda@gmail.com', '123abc4534!@#', 'Yoda', 'Grandmaster Jedi').text)
    # Create New Channel
    new_dm = json.loads(post_dm_create(first_user['token'], [second_user['auth_user_id']]).text)

    return {'first_user' : first_user, 'second_user' : second_user, 'new_dm' : new_dm, 'third_user': third_user}

@pytest.fixture(scope='function')
def setup1():
    requests.delete(config.url + 'clear/v1')
    requests.post(config.url + 'auth/register/v2', json={"email" : "testuser1@gmail.com", 'password' : 'testuser1password', 'name_first' : 'Test User', 'name_last' : '1'})
    login_response = json.loads(requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password'}).text)
    token_1 = login_response

    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password', 'name_first' : 'Test User', 'name_last' : '2'})
    login_response_2 = json.loads(requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password'}).text)
    token_2 = login_response_2

    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password', 'name_first' : 'Test User', 'name_last' : '3'})
    login_response_3 = json.loads(requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password'}).text)
    token_3 = login_response_3

    dm_create = json.loads(requests.post(config.url + 'dm/create/v1', json={'token' : token_1['token'], 'u_ids' : [2,3]}).text)
    # Create a dm for all three users
    # Return a list containing the tokens of each user
    return [token_1['token'], token_2['token'], token_3['token'], dm_create]


# Raf iteration 3
@pytest.fixture(scope='function')
def setup2():
    # register and log 4 uesrs in
    requests.delete(config.url + 'clear/v1')
    
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password', 'name_first' : 'Test User', 'name_last' : '1'})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password', 'name_first' : 'Test User', 'name_last' : '2'})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password', 'name_first' : 'Test User', 'name_last' : '3'})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser4@gmail.com', 'password' : 'testuser4password', 'name_first' : 'Test User', 'name_last' : '4'})

    login1_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password'})
    login1_token = login1_response.json()
    login2_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password'})
    login2_token = login2_response.json()
    login3_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password'})
    login3_token = login3_response.json()
    login4_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser4@gmail.com', 'password' : 'testuser4password'})
    login4_token = login4_response.json()

    return [login1_token['token'], login2_token['token'], login3_token['token'], login4_token['token']]

#############################################
# message_send_v1 Tests
#############################################

# Test that an invalid channel id comes up with an input error
def test_invalid_channel_id_message_send_v1(setup):
    assert(post_message_send(setup['first_user']['token'], INVALID_ID, NORMAL_MESSAGE).status_code == INPUTERROR)

# Test that a message less than one character comes up with an input error
def test_message_length_less_than_one_message_send_v1(setup):
    assert(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NO_CHARACTER_MESSAGE).status_code == INPUTERROR)

# Test that a message greater than one character comes up with an input error
def test_message_length_greater_than_thousand_message_send_v1(setup):
    assert(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], THOUSAND_CHARACTER_MESSAGE).status_code == INPUTERROR)

# Test that when channel_id is valid but the user is unauthorized, show an access error
def test_unauthorised_user_message_send_v1(setup):
    assert(post_message_send(setup['second_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).status_code == ACCESSERROR)

# Test that an invalid token shows an access error
def test_invalid_token_message_send_v1(setup):
    assert((post_message_send(INVALID_TOKEN, setup['new_channel']['channel_id'], NORMAL_MESSAGE).status_code == ACCESSERROR))

# Test that a valid message shows no errors and returns intended output
def test_valid_message_send_v1(setup):
    assert(json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)['message_id'] == 0)
    messages = json.loads(get_channel_messages(setup['first_user']['token'], setup['new_channel']['channel_id'], 0).text)
    assert(messages['messages'][0]['message'] == NORMAL_MESSAGE)

# Test that a normal member can also send a message
def test_valid_2_message_send_v1(setup):
    post_channel_invite(setup['first_user']['token'], setup['new_channel']['channel_id'], setup['third_user']['auth_user_id'])
    post_channel_invite(setup['first_user']['token'], setup['new_channel']['channel_id'], setup['second_user']['auth_user_id'])
    assert(json.loads(post_message_send(setup['second_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)['message_id'] == 0)
    messages = json.loads(get_channel_messages(setup['second_user']['token'], setup['new_channel']['channel_id'], 0).text)
    assert(messages['messages'][0]['message'] == NORMAL_MESSAGE)

#############################################
# message_edit_v1 Tests
#############################################

# Test that a message with length over 1000 characters shows an input error
def test_length_of_message_greater_than_thousand_message_edit_v1(setup):
    one_message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    assert(put_message_edit_v1(setup['first_user']['token'], one_message_id['message_id'], THOUSAND_CHARACTER_MESSAGE).status_code == INPUTERROR)

# Test that a message in another channel that the user does not have access to shows an input error
def test_message_is_in_another_channel_message_edit_v1(setup):
    second_channel = json.loads(post_channels_create(setup["second_user"]['token'], "channel", True).text)
    one_message_id = json.loads(post_message_send(setup['second_user']['token'], second_channel['channel_id'], NORMAL_MESSAGE).text)
    assert(put_message_edit_v1(setup['first_user']['token'], one_message_id['message_id'], NORMAL_MESSAGE).status_code == INPUTERROR)

# Test that an invalid token shows an access error
def test_invalid_token_message_edit_v1(setup):
    one_message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    assert((put_message_edit_v1(INVALID_TOKEN, one_message_id['message_id'], NORMAL_MESSAGE).status_code == ACCESSERROR))

# Test that an unauthorised user can't edit the message
def test_unauthorised_user_message_edit_v1(setup):
    one_message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    post_channel_invite(setup['first_user']['token'], setup['new_channel']['channel_id'], setup['second_user']['auth_user_id'])
    # Check for Access Error for an unauthorised user
    assert(put_message_edit_v1(setup['second_user']['token'], one_message_id['message_id'], NORMAL_MESSAGE).status_code == ACCESSERROR)

    # Check that an owner can successfully edit the message
    post_channel_add_owner_v1(setup['first_user']['token'], setup['new_channel']['channel_id'], setup['second_user']['auth_user_id'])
    assert(json.loads(put_message_edit_v1(setup['second_user']['token'], one_message_id['message_id'], NORMAL_MESSAGE).text) == {})

    # Check that the original sender can successfully edit the message
    assert(json.loads(put_message_edit_v1(setup['first_user']['token'], one_message_id['message_id'], NORMAL_MESSAGE).text) == {})

# Test that the edit message functions works as expected
def test_valid_message_edit_v1(setup):
    post_channel_invite(setup['first_user']['token'], setup['new_channel']['channel_id'], setup['second_user']['auth_user_id'])
    post_message_send(setup['second_user']['token'], setup['new_channel']['channel_id'], 'first message')
    one_message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    assert(json.loads(put_message_edit_v1(setup['first_user']['token'], one_message_id['message_id'], NORMAL_MESSAGE).text) == {})
    messages = json.loads(get_channel_messages(setup['first_user']['token'], setup['new_channel']['channel_id'], 0).text)
    assert(messages['messages'][1]['message'] == NORMAL_MESSAGE)

# Test that the edit message functions works as expected for a dm
def test_valid_2_message_edit_v1(setup):
    dm_id = json.loads(post_dm_create(setup['first_user']['token'], [setup['second_user']['auth_user_id']]).text)
    one_message_id = json.loads(post_message_senddm(setup['first_user']['token'], dm_id['dm_id'], NORMAL_MESSAGE).text)
    assert(json.loads(put_message_edit_v1(setup['first_user']['token'], one_message_id['message_id'], NORMAL_MESSAGE).text) == {})
    messages = json.loads(get_dm_messages(setup['first_user']['token'], dm_id['dm_id'], 0).text)
    assert(messages['messages'][0]['message'] == NORMAL_MESSAGE)

# Test that the edit message functions work for multiple members in a dm
def test_valid_3_message_edit_v1(setup):
    dm_id = json.loads(post_dm_create(setup['first_user']['token'], [setup['third_user']['auth_user_id'], setup['second_user']['auth_user_id']]).text)
    one_message_id = json.loads(post_message_senddm(setup['second_user']['token'], dm_id['dm_id'], NORMAL_MESSAGE).text)

    # Check that an owner can successfully edit the message
    assert(json.loads(put_message_edit_v1(setup['first_user']['token'], one_message_id['message_id'], NORMAL_MESSAGE).text) == {})

    # Check that the original sender can successfully edit the message
    assert(json.loads(put_message_edit_v1(setup['second_user']['token'], one_message_id['message_id'], NORMAL_MESSAGE).text) == {})

#############################################
# message_remove_v1 Tests
#############################################

# Test that a message in another channel that the user does not have access to does not get removed and throws an input error
def test_message_is_in_another_channel_message_remove_v1(setup):
    second_channel = json.loads(post_channels_create(setup["second_user"]['token'], "channel", True).text)
    one_message_id = json.loads(post_message_send(setup['second_user']['token'], second_channel['channel_id'], NORMAL_MESSAGE).text)
    assert(delete_message_remove_v1(setup['first_user']['token'], one_message_id['message_id']).status_code == INPUTERROR)

# Test that an invalid token shows an access error
def test_invalid_token_message_remove_v1(setup):
    one_message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    assert((delete_message_remove_v1(INVALID_TOKEN, one_message_id['message_id']).status_code == ACCESSERROR))

# Test that an access error is thrown for an unauthorised user
def test_unauthorised_user_message_remove_dm(setup):
    dm_id = json.loads(post_dm_create(setup['first_user']['token'], [setup['second_user']['auth_user_id']]).text)
    one_message_id = json.loads(post_message_senddm(setup['first_user']['token'], dm_id['dm_id'], NORMAL_MESSAGE).text)

    # Check for Access Error for an unauthorised user
    assert(delete_message_remove_v1(setup['second_user']['token'], one_message_id['message_id']).status_code == ACCESSERROR)


# Test that an access error is thrown for an unauthorised user
def test_unauthorised_user_message_remove_v1(setup):
    one_message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    post_channel_invite(setup['first_user']['token'], setup['new_channel']['channel_id'], setup['second_user']['auth_user_id'])
    # Check for Access Error for an unauthorised user
    assert(delete_message_remove_v1(setup['second_user']['token'], one_message_id['message_id']).status_code == ACCESSERROR)

    # Check that an owner can successfully remove the message
    post_channel_add_owner_v1(setup['first_user']['token'], setup['new_channel']['channel_id'], setup['second_user']['auth_user_id'])
    assert(json.loads(delete_message_remove_v1(setup['second_user']['token'], one_message_id['message_id']).text) == {})

# Test that the request works as expected
def test_valid_message_remove_v1(setup):
    second_channel = json.loads(post_channels_create(setup['second_user']['token'], "channel2", True).text)
    one_message_id = json.loads(post_message_send(setup['second_user']['token'], second_channel['channel_id'], NORMAL_MESSAGE).text)
    assert(json.loads(delete_message_remove_v1(setup['second_user']['token'], one_message_id['message_id']).text) == {})
    messages = json.loads(get_channel_messages(setup['second_user']['token'], second_channel['channel_id'], 0).text)
    assert(messages['messages'] == [])

# Test that the remove message functions works as expected for a dm
def test_valid_2_message_remove_v1(setup):
    dm_id = json.loads(post_dm_create(setup['first_user']['token'], [setup['second_user']['auth_user_id']]).text)
    one_message_id = json.loads(post_message_senddm(setup['first_user']['token'], dm_id['dm_id'], NORMAL_MESSAGE).text)
    assert(json.loads(delete_message_remove_v1(setup['first_user']['token'], one_message_id['message_id']).text) == {})
    messages = json.loads(get_channel_messages(setup['first_user']['token'], setup['new_channel']['channel_id'], 0).text)
    assert(messages['messages'] == [])

# Test that the remove message functions work for multiple members in a dm
def test_valid_3_message_remove_v1(setup):
    fourth_user = json.loads(post_register('bruh2@gmail.com', '123abc4534!@#', 'Zeal', 'Man').text)
    post_dm_create(setup['first_user']['token'], [fourth_user['auth_user_id'], setup['second_user']['auth_user_id']])
    dm_id = json.loads(post_dm_create(setup['first_user']['token'], [setup['third_user']['auth_user_id'], setup['second_user']['auth_user_id']]).text)
    one_message_id = json.loads(post_message_senddm(setup['second_user']['token'], dm_id['dm_id'], NORMAL_MESSAGE).text)

    # Check that an owner can successfully remove the message
    assert(json.loads(delete_message_remove_v1(setup['first_user']['token'], one_message_id['message_id']).text) == {})

#############################################
# message/senddm/v1 Tests
#############################################
# Invalid token, valid id, valid message
def test_invalid_token_sd(setup1):
    message_response = requests.post(config.url + "message/senddm/v1", json={'token' : INVALID_TOKEN, "dm_id" : (setup1[3])['dm_id'], "message" : "Hello World!"})
    assert message_response.status_code == 403

# Valid token, invalid id, valid message
def test_invalid_dm_id_sd(setup1):
    message_response = requests.post(config.url + "message/senddm/v1", json={'token' : setup1[0], "dm_id" : INVALID_ID, "message" : "Hello World!"})
    assert message_response.status_code == 400

# Valid token, valid id, invalid message
def test_invalid_message_sd(setup1):
    # Invalid message -> len(message) < 1
    empty_message_response = requests.post(config.url + "message/senddm/v1", json={'token' : setup1[0], "dm_id" : (setup1[3])['dm_id'], "message" : ""})
    assert empty_message_response.status_code == 400

    # Generate a message that is 1002 characters long
    long_message = ''.join([choice(string.ascii_letters) for c in range(1002)])
    # Invalid message -> len(message) > 1000
    long_message_response = requests.post(config.url + "message/senddm/v1", json={'token' : setup1[0], "dm_id" : (setup1[3])['dm_id'], 'message' : long_message})
    assert long_message_response.status_code == 400

# Valid token, valid id, valid message but the user associated with the token is not a member of the
# dm tied to dm_id
def test_invalid_membership_sd(setup1):
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser4@gmail.com', 'password' : 'testuser4password', 'name_first' : 'Test User', 'name_last' : "4"})
    login_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser4@gmail.com', 'password' : 'testuser4password'})
    non_member_token = login_response.json()

    non_member_response = requests.post(config.url + "message/senddm/v1", json={'token' : non_member_token['token'], "dm_id" : (setup1[3])['dm_id'], 'message' : 'Hello World!'})
    assert non_member_response.status_code == 403

# Successfully send one message to a valid dm
def test_send_one_message_sd(setup1):
    message_response = requests.post(config.url + "message/senddm/v1", json={'token' : setup1[0], "dm_id" : (setup1[3])['dm_id'], "message" : "Hello World!"})
    message_result = message_response.json()
    assert message_result == {'message_id' : 0}

# Successfully send multiple messages to a valid dm
def test_send_multiple_dm_messages_sd(setup1):
    for i in range(3):
        message_response = requests.post(config.url + "message/senddm/v1", json={'token' : setup1[0], 'dm_id' : (setup1[3])['dm_id'], "message" : "Hello World!"})
        message_result = message_response.json()
        assert message_result == {'message_id' : i}

# Each user in a dm sends a message
def test_send_message_each_user_sd(setup1):
    for i in range(3):
        message_response = requests.post(config.url + "message/senddm/v1", json={'token' : setup1[i], 'dm_id' : (setup1[3])['dm_id'], "message" : "Hello from user " + str(i+1)})
        message_result = message_response.json()
        assert message_result == {'message_id' : i}

#############################################
# message/share/v1 Tests
#############################################
def test_invalid_token_share(setup2):
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    c1_id = channel_create.json()

    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3,4]})
    dm_id = dm_create.json()

    message = requests.post(config.url  + 'message/send/v1', json={'token' : setup2[0], 'channel_id' : c1_id['channel_id'], 'message' : MESSAGE})
    m_id = message.json()

    share_response = requests.post(config.url + 'message/share/v1', json={'token' : INVALID_TOKEN, 'og_message_id' : m_id['message_id'], 'message' : NO_CHARACTER_MESSAGE, 'channel_id' : -1, 'dm_id' : dm_id['dm_id']})
    assert share_response.status_code == ACCESSERROR

def test_invalid_channel_and_dm_share(setup2):
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    c1_id = channel_create.json()

    requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3,4]})

    message = requests.post(config.url  + 'message/send/v1', json={'token' : setup2[0], 'channel_id' : c1_id['channel_id'], 'message' : MESSAGE})
    m_id = message.json()
    share_response = requests.post(config.url + 'message/share/v1', json={'token' : setup2[0], 'og_message_id' : m_id['message_id'], 'message' : NO_CHARACTER_MESSAGE, 'channel_id' : INVALID_ID, 'dm_id' : INVALID_ID})
    assert share_response.status_code == INPUTERROR

def test_both_channel_and_id_share(setup2):
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    c1_id = channel_create.json()

    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3,4]})
    dm_id = dm_create.json()

    message = requests.post(config.url  + 'message/send/v1', json={'token' : setup2[0], 'channel_id' : c1_id['channel_id'], 'message' : MESSAGE})
    m_id = message.json()
    share_response = requests.post(config.url + 'message/share/v1', json={'token' : setup2[0], 'og_message_id' : m_id['message_id'], 'message' : NO_CHARACTER_MESSAGE, 'channel_id' : c1_id['channel_id'], 'dm_id' : dm_id['dm_id']})
    assert share_response.status_code == INPUTERROR

def test_invalid_message_id_share(setup2):
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    c1_id = channel_create.json()

    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3,4]})
    dm_id = dm_create.json()

    requests.post(config.url  + 'message/send/v1', json={'token' : setup2[0], 'channel_id' : c1_id['channel_id'], 'message' : MESSAGE})
    share_response = requests.post(config.url + 'message/share/v1', json={'token' : setup2[0], 'og_message_id' : INVALID_ID, 'message' : NO_CHARACTER_MESSAGE, 'channel_id' : INVALID_ID, 'dm_id' : dm_id['dm_id']})
    assert share_response.status_code == INPUTERROR

def test_invalid_message_length_share(setup2):
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    c1_id = channel_create.json()

    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3,4]})
    dm_id = dm_create.json()

    message = requests.post(config.url  + 'message/send/v1', json={'token' : setup2[0], 'channel_id' : c1_id['channel_id'], 'message' : MESSAGE})
    m_id = message.json()
    share_response = requests.post(config.url + 'message/share/v1', json={'token' : setup2[0], 'og_message_id' : m_id['message_id'], 'message' : THOUSAND_CHARACTER_MESSAGE, 'channel_id' : INVALID_ID, 'dm_id' : dm_id['dm_id']})
    assert share_response.status_code == INPUTERROR


def test_not_a_member_channel_share(setup2):
    # share a message from a dm to a channel that the user is not a member of
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    c1_id = channel_create.json()

    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3,4]})
    dm_id = dm_create.json()

    message = requests.post(config.url  + 'message/senddm/v1', json={'token' : setup2[0], 'dm_id' : dm_id['dm_id'], 'message' : MESSAGE})
    m_id = message.json()

    share_response = requests.post(config.url + 'message/share/v1', json={'token' : setup2[1], 'og_message_id' : m_id['message_id'], 'message' : NO_CHARACTER_MESSAGE, 'channel_id' : c1_id['channel_id'], 'dm_id' : -1})
    assert share_response.status_code == ACCESSERROR

def test_not_a_member_dm_share(setup2):
    # sharea  a message from a channel to a dm that the user is not a member of
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    c1_id = channel_create.json()

    requests.post(config.url + 'channel/join/v2', json={'token' : setup2[3], 'channel_id' : c1_id['channel_id']})

    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3]})
    dm_id = dm_create.json()

    message = requests.post(config.url  + 'message/send/v1', json={'token' : setup2[0], 'channel_id' : c1_id['channel_id'], 'message' : MESSAGE})
    m_id = message.json()

    share_response = requests.post(config.url + 'message/share/v1', json={'token' : setup2[3], 'og_message_id' : m_id['message_id'], 'message' : NO_CHARACTER_MESSAGE, 'channel_id' : -1, 'dm_id' : dm_id['dm_id']})
    assert share_response.status_code == ACCESSERROR

def test_share_with_empty_share(setup2):
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    c1_id = channel_create.json()

    requests.post(config.url + 'channel/join/v2', json={'token' : setup2[3], 'channel_id' : c1_id['channel_id']})

    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3,4]})
    dm_id = dm_create.json()

    message = requests.post(config.url  + 'message/send/v1', json={'token' : setup2[0], 'channel_id' : c1_id['channel_id'], 'message' : MESSAGE})
    m_id = message.json()

    share_response = requests.post(config.url + 'message/share/v1', json={'token' : setup2[3], 'og_message_id' : m_id['message_id'], 'message' : NO_CHARACTER_MESSAGE, 'channel_id' : -1, 'dm_id' : dm_id['dm_id']})
    share_result = share_response.json()
    assert share_result == {'shared_message_id' : 1}

def test_share_dm_to_dm_share(setup2):
    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3,4]})
    dm1_id = dm_create.json()

    dm2_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3]})
    dm2_id = dm2_create.json()

    message = requests.post(config.url  + 'message/senddm/v1', json={'token' : setup2[0], 'dm_id' : dm1_id['dm_id'], 'message' : MESSAGE})
    m_id = message.json()

    time = datetime.now().strftime('%d/%m/%Y, %H:%M:%S')   
    share_response = requests.post(config.url + 'message/share/v1', json={'token' : setup2[1], 'og_message_id' : m_id['message_id'], 'message' : NO_CHARACTER_MESSAGE, 'channel_id' : -1, 'dm_id' : dm2_id['dm_id']})
    share_result = share_response.json()
    assert share_result == {'shared_message_id' : 1}
    messages_response = requests.get(config.url + 'dm/messages/v1', params={'token' : setup2[0], 'dm_id' : dm2_id['dm_id'], 'start' : 0})
    messages = messages_response.json()
    assert messages['messages'] == [
            {
                'message_id' : 1,
                'u_id' : 2,
                'message' : MESSAGE,
                'time_created' : time,
                'reacts' : [],
                'is_pinned' : False
            }
        ]

def test_share_dm_to_channel_share(setup2):
    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3,4]})
    dm1_id = dm_create.json()

    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    c_id = channel_create.json()


    message = requests.post(config.url  + 'message/senddm/v1', json={'token' : setup2[0], 'dm_id' : dm1_id['dm_id'], 'message' : MESSAGE})
    m_id = message.json()

    time2 = datetime.now().strftime('%d/%m/%Y, %H:%M:%S')   
    share_response = requests.post(config.url + 'message/share/v1', json={'token' : setup2[0], 'og_message_id' : m_id['message_id'], 'message' : NO_CHARACTER_MESSAGE, 'channel_id' : c_id['channel_id'], 'dm_id' : -1})
    share_result = share_response.json()
    assert share_result == {'shared_message_id' : 1}

    messages_response = requests.get(config.url + 'channel/messages/v2', params={'token' : setup2[0], 'channel_id' : c_id['channel_id'], 'start' : 0})
    messages = messages_response.json()
    assert messages['messages'] == [
            {
                'message_id' : 1,
                'u_id' : 1,
                'message' : MESSAGE,
                'time_created' : time2,
                'reacts' : [],
                'is_pinned' : False
            }
        ]

def test_share_channel_to_dm_share(setup2):
    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3,4]})
    dm1_id = dm_create.json()

    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    c_id = channel_create.json()

    message = requests.post(config.url  + 'message/send/v1', json={'token' : setup2[0], 'channel_id' : c_id['channel_id'], 'message' : MESSAGE})
    m_id = message.json()

    time = datetime.now().strftime('%d/%m/%Y, %H:%M:%S')   
    share_response = requests.post(config.url + 'message/share/v1', json={'token' : setup2[0], 'og_message_id' : m_id['message_id'], 'message' : NO_CHARACTER_MESSAGE, 'channel_id' : -1, 'dm_id' : dm1_id['dm_id']})
    share_result = share_response.json()
    assert share_result == {'shared_message_id' : 1}

    messages_response = requests.get(config.url + 'dm/messages/v1', params={'token' : setup2[0], 'dm_id' : dm1_id['dm_id'], 'start' : 0})
    messages = messages_response.json()
    assert messages['messages'] == [
            {
                'message_id' : 1,
                'u_id' : 1,
                'message' : MESSAGE,
                'time_created' : time,
                'reacts' : [],
                'is_pinned' : False
            }
        ]

def test_share_channel_to_channel_share(setup2):
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    c1_id = channel_create.json()
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 2', 'is_public' : True})
    c2_id = channel_create.json()

    time = datetime.now().strftime('%d/%m/%Y, %H:%M:%S')    
    message = requests.post(config.url  + 'message/send/v1', json={'token' : setup2[0], 'channel_id' : c1_id['channel_id'], 'message' : MESSAGE})
    m_id = message.json()

    time2 = datetime.now().strftime('%d/%m/%Y, %H:%M:%S')    
    share_response = requests.post(config.url + 'message/share/v1', json={'token' : setup2[0], 'og_message_id' : m_id['message_id'], 'message' : NO_CHARACTER_MESSAGE, 'channel_id' : c2_id['channel_id'], 'dm_id' : -1})
    share_result = share_response.json()
    assert share_result == {'shared_message_id' : 1}

    messages_response = requests.get(config.url + 'channel/messages/v2', params={'token' : setup2[0], 'channel_id' : c2_id['channel_id'], 'start' : 0})
    messages = messages_response.json()
    assert messages['messages'] == [
            {
                'message_id' : 0,
                'u_id' : 1,
                'message' : MESSAGE,
                'time_created' : time,
                'reacts' : [],
                'is_pinned' : False
            },
            {
                'message_id' : 1,
                'u_id' : 1,
                'message' : MESSAGE,
                'time_created' : time2,
                'reacts' : [],
                'is_pinned' : False
            }
        ]


#############################################
# message_sendlater_v1 Tests
#############################################
def test_invalid_token_sl(setup2):
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    channel_id = channel_create.json()['channel_id']

    target_users = setup2[1: ]
    for u in target_users:
        requests.post(config.url + 'channel/join/v2', json={'token' : u, 'channel_id' : channel_id})
    t = time.time() + 15 # schedule a message for 15 seconds from now
    send_later_response = requests.post(config.url + 'message/sendlater/v1', json={'token' : INVALID_TOKEN, 'channel_id' : channel_id, 'message' : MESSAGE, 'time_sent' : int(t)})
    assert send_later_response.status_code == ACCESSERROR

def test_not_channel_member_sl(setup2):
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    channel_id = channel_create.json()['channel_id']
    target_users = setup2[1: ]
    for u in target_users:
        t = time.time() + 15 # schedule a message for 15 seconds from now
        send_later_response = requests.post(config.url + 'message/sendlater/v1', json={'token' : u, 'channel_id' : channel_id, 'message' : MESSAGE, 'time_sent' : int(t)})
        assert send_later_response.status_code == ACCESSERROR

def test_invalid_channel_id_sl(setup2):
    for u in setup2:
        t = time.time() + 15 # schedule a message for 15 seconds from now
        send_later_response = requests.post(config.url + 'message/sendlater/v1', json={'token' : u, 'channel_id' : INVALID_ID, 'message' : MESSAGE, 'time_sent' : int(t)})
        assert send_later_response.status_code == INPUTERROR

def test_invalid_message_sl(setup2):
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    channel_id = channel_create.json()['channel_id']

    target_users = setup2[1: ]
    for u in target_users:
        requests.post(config.url + 'channel/join/v2', json={'token' : u, 'channel_id' : channel_id})
    for u in setup2:
        t = time.time() + 15 #schedule a message for 15 seconds from now
        send_later_empty = requests.post(config.url + 'message/sendlater/v1', json={'token' : u, 'channel_id' : channel_id, 'message' : NO_CHARACTER_MESSAGE, 'time_sent' : int(t)})
        assert send_later_empty.status_code == INPUTERROR
        send_later_1001 = requests.post(config.url + 'message/sendlater/v1', json={'token' : u, 'channel_id' : channel_id, 'message' : THOUSAND_CHARACTER_MESSAGE, 'time_sent' : int(t)})
        assert send_later_1001.status_code == INPUTERROR
def test_invalid_time_sl(setup2):
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    channel_id = channel_create.json()['channel_id']

    target_users = setup2[1: ]
    for u in target_users:
        requests.post(config.url + 'channel/join/v2', json={'token' : u, 'channel_id' : channel_id})
    for u in setup2:
        t = time.time() - 100 #schedule a message for 15 seconds from now
        send_later_empty = requests.post(config.url + 'message/sendlater/v1', json={'token' : u, 'channel_id' : channel_id, 'message' : MESSAGE, 'time_sent' : int(t)})
        assert send_later_empty.status_code == INPUTERROR
        send_later_1001 = requests.post(config.url + 'message/sendlater/v1', json={'token' : u, 'channel_id' : channel_id, 'message' : MESSAGE, 'time_sent' : int(t)})
        assert send_later_1001.status_code == INPUTERROR



def test_5_seconds_single_sl(setup2):
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup2[0], 'name' : 'Test Channel 1', 'is_public' : True})
    channel_id = channel_create.json()['channel_id']

    target_users = setup2[1: ]
    for u in target_users:
        requests.post(config.url + 'channel/join/v2', json={'token' : u, 'channel_id' : channel_id})
    t = time.time() + 5 # schedule a message for 15 seconds from now
    send_later_response = requests.post(config.url + 'message/sendlater/v1', json={'token' : setup2[0], 'channel_id' : channel_id, 'message' : MESSAGE + ' later', 'time_sent' : int(t)})
    send_later = send_later_response.json()
    assert send_later == {'message_id' : 0}
    time.sleep(10)
    requests.post(config.url + 'message/send/v1', json={'token' : setup2[0], 'channel_id' : channel_id, 'message' : MESSAGE})
    # get the channel messages, and check that the delayed
    messages_response = requests.get(config.url + 'channel/messages/v2', params={'token' : setup2[0], 'channel_id' : channel_id, 'start' : 0})
    messages = messages_response.json()

    assert messages['messages'] == [
        {
            'message_id' : 1,
            'u_id' : 1,
            'message' : MESSAGE,
            'time_created' : datetime.now().strftime('%d/%m/%Y, %H:%M:%S'),
            'reacts' : [],
            'is_pinned' : False
        },
        {
            'message_id' : 2,
            'u_id' : 1,
            'message' : MESSAGE  + ' later',
            'time_created' : datetime.now().strftime('%d/%m/%Y, %H:%M:%S'),
            'reacts' : [],
            'is_pinned' : False
        }
    ]    

#############################################
# message_sendlaterdm_v1 Tests
#############################################
def test_invalid_token_sldm(setup2):
    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[2], 'u_ids' : [2,3,4]})
    dm_id = dm_create.json()['dm_id']

    t = time.time() + 15
    send_later_dm = requests.post(config.url + 'message/sendlaterdm/v1', json={'token' : INVALID_TOKEN, 'dm_id' : dm_id, 'message' : MESSAGE, 'time_sent' : int(t)})
    assert send_later_dm.status_code == ACCESSERROR

def test_not_dm_member_sldm(setup2):
    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[2], 'u_ids' : [2,3]})
    dm_id = dm_create.json()['dm_id']

    t = time.time() + 15
    send_later_dm = requests.post(config.url + 'message/sendlaterdm/v1', json={'token' : setup2[-1], 'dm_id' : dm_id, 'message' : MESSAGE, 'time_sent' : int(t)})
    assert send_later_dm.status_code == ACCESSERROR

def test_invalid_dm_id_sldm(setup2):
    requests.post(config.url + 'dm/create/v1', json={'token' : setup2[2], 'u_ids' : [2,3,4]})
    t = time.time() + 15
    send_later_dm = requests.post(config.url + 'message/sendlaterdm/v1', json={'token' : setup2[2], 'dm_id' : INVALID_ID, 'message' : MESSAGE, 'time_sent' : int(t)})
    assert send_later_dm.status_code == INPUTERROR

def test_invalid_message_sldm(setup2):
    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3,4]})
    dm_id = dm_create.json()['dm_id']

    for u in setup2:
        t = time.time() + 15
        send_later_dm_empty = requests.post(config.url + 'message/sendlaterdm/v1', json={'token' : u, 'dm_id' : dm_id, 'message' : NO_CHARACTER_MESSAGE, 'time_sent' : int(t)})
        assert send_later_dm_empty.status_code == INPUTERROR
        send_later_dm_1001 = requests.post(config.url + 'message/sendlaterdm/v1', json={'token' : u, 'dm_id' : dm_id, 'message' : THOUSAND_CHARACTER_MESSAGE, 'time_sent' : int(t)})
        assert send_later_dm_1001.status_code == INPUTERROR

def test_invalid_time_sldm(setup2):
    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3,4]})
    dm_id = dm_create.json()['dm_id']

    for u in setup2:
        t = time.time() - 10000
        send_later_dm_ = requests.post(config.url + 'message/sendlaterdm/v1', json={'token' : u, 'dm_id' : dm_id, 'message' : NO_CHARACTER_MESSAGE, 'time_sent' : int(t)})
        assert send_later_dm_.status_code == INPUTERROR


def test_5_seconds_single_sldm(setup2):
    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3,4]})
    dm_id = dm_create.json()['dm_id']

    t = time.time() + 5 # schedule a message for 15 seconds from now
    send_later_response = requests.post(config.url + 'message/sendlaterdm/v1', json={'token' : setup2[0], 'dm_id' : dm_id, 'message' : MESSAGE + ' later', 'time_sent' : int(t)})
    send_later = send_later_response.json()
    assert send_later == {'message_id' : 0}
    
    time.sleep(10)
    # get the channel messages, and check that the delayed
    requests.post(config.url + 'message/senddm/v1', json={'token' : setup2[0], 'dm_id' : dm_id, 'message' : MESSAGE})
    # get the channel messages, and check that the delayed
    messages_response = requests.get(config.url + 'dm/messages/v1', params={'token' : setup2[0], 'dm_id' : dm_id, 'start' : 0})
    messages = messages_response.json()

    assert messages['messages'] == [
        {
            'message_id' : 2,
            'u_id' : 1,
            'message' : MESSAGE + ' later',
            'time_created' : datetime.now().strftime('%d/%m/%Y, %H:%M:%S'),
            'reacts' : [],
            'is_pinned' : False
        },
        {
            'message_id' : 1,
            'u_id' : 1,
            'message' : MESSAGE,
            'time_created' : datetime.now().strftime('%d/%m/%Y, %H:%M:%S'),
            'reacts' : [],
            'is_pinned' : False
        }
    ]   

#############################################
# message_react_v1 Tests
#############################################

# Test input error is raised when message_id is not a valid message within a channel or DM that the authorised user has joined
def test_invalid_message_id_message_react_v1_channel(setup):
    second_channel = json.loads(post_channels_create(setup['first_user']['token'], "channel", True).text)
    message_id = json.loads(post_message_send(setup['first_user']['token'], second_channel['channel_id'], NORMAL_MESSAGE).text)
    assert post_message_react_v1(setup['second_user']['token'], message_id['message_id'], VALID_REACT).status_code == INPUTERROR
    assert post_message_react_v1(setup['second_user']['token'], INVALID_ID, VALID_REACT).status_code == INPUTERROR
    
def test_invalid_message_id_message_react_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    assert post_message_react_v1(setup_dm['third_user']['token'], message_id['message_id'], VALID_REACT).status_code == INPUTERROR
    
# Test input error is raised when react_id is not a valid react ID
def test_invalid_react_id_message_react_v1_channel(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    assert post_message_react_v1(setup['first_user']['token'], message_id['message_id'], INVALID_REACT).status_code == INPUTERROR

def test_invalid_react_id_message_react_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    assert post_message_react_v1(setup_dm['first_user']['token'], message_id['message_id'], INVALID_REACT).status_code == INPUTERROR

# Test input error is raised when the message already contains a react with ID react_id from the authorised user
def test_message_already_has_same_react_message_react_v1_channel(setup):    
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    post_message_react_v1(setup['first_user']['token'], message_id['message_id'], VALID_REACT)
    assert post_message_react_v1(setup['first_user']['token'], message_id['message_id'], VALID_REACT).status_code == INPUTERROR

def test_message_already_has_same_react_message_react_v1_dm(setup_dm):    
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    post_message_react_v1(setup_dm['first_user']['token'], message_id['message_id'], VALID_REACT)
    assert post_message_react_v1(setup_dm['first_user']['token'], message_id['message_id'], VALID_REACT).status_code == INPUTERROR

# Test access error is raised when an invalid token is given
def test_invalid_token_message_react_v1(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    assert post_message_react_v1(INVALID_TOKEN, message_id['message_id'], VALID_REACT).status_code == ACCESSERROR

# Test that the function works as expected
def test_valid_message_react_v1_channel(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)

    # Test that channel owner can react
    assert json.loads(post_message_react_v1(setup['first_user']['token'], message_id['message_id'], VALID_REACT).text) == {}
    messages = json.loads(get_channel_messages(setup['first_user']['token'], setup['new_channel']['channel_id'], 0).text)
    assert messages['messages'][0]['reacts'] == [{'is_this_user_reacted': True, 'react_id': 1, 'u_ids': [1]}]

    # Test that channel member can react
    post_channel_invite(setup['first_user']['token'], setup['new_channel']['channel_id'], setup['second_user']['auth_user_id'])
    assert json.loads(post_message_react_v1(setup['second_user']['token'], message_id['message_id'], VALID_REACT).text) == {}
    messages = json.loads(get_channel_messages(setup['second_user']['token'], setup['new_channel']['channel_id'], 0).text)
    assert messages['messages'][0]['reacts'] == [{'is_this_user_reacted': True, 'react_id': 1, 'u_ids': [1, 2]}]

    # Remove reacts
    post_message_unreact_v1(setup['first_user']['token'], message_id['message_id'], VALID_REACT)
    post_message_unreact_v1(setup['second_user']['token'], message_id['message_id'], VALID_REACT)

    # Test that channel member can react on their own
    assert json.loads(post_message_react_v1(setup['second_user']['token'], message_id['message_id'], VALID_REACT).text) == {}
    messages = json.loads(get_channel_messages(setup['second_user']['token'], setup['new_channel']['channel_id'], 0).text)
    assert messages['messages'][0]['reacts'] == [{'is_this_user_reacted': False, 'react_id': 1, 'u_ids': [2]}]

    # Test that channel owner can react after a member
    assert json.loads(post_message_react_v1(setup['first_user']['token'], message_id['message_id'], VALID_REACT).text) == {}
    messages = json.loads(get_channel_messages(setup['first_user']['token'], setup['new_channel']['channel_id'], 0).text)
    assert messages['messages'][0]['reacts'] == [{'is_this_user_reacted': True, 'react_id': 1, 'u_ids': [2, 1]}]

def test_valid_message_react_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)

    # Test that channel owner can react
    assert json.loads(post_message_react_v1(setup_dm['first_user']['token'], message_id['message_id'], VALID_REACT).text) == {}
    messages = json.loads(get_dm_messages(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], 0).text)
    assert messages['messages'][0]['reacts'] == [{'is_this_user_reacted': True, 'react_id': 1, 'u_ids': [1]}]

    # Test that channel member can react
    assert json.loads(post_message_react_v1(setup_dm['second_user']['token'], message_id['message_id'], VALID_REACT).text) == {}
    messages = json.loads(get_dm_messages(setup_dm['second_user']['token'], setup_dm['new_dm']['dm_id'], 0).text)
    assert messages['messages'][0]['reacts'] == [{'is_this_user_reacted': True, 'react_id': 1, 'u_ids': [1, 2]}]

    # Remove previous reacts
    post_message_unreact_v1(setup_dm['first_user']['token'], message_id['message_id'], VALID_REACT)
    post_message_unreact_v1(setup_dm['second_user']['token'], message_id['message_id'], VALID_REACT)

    # Test that channel member can react on their own
    assert json.loads(post_message_react_v1(setup_dm['second_user']['token'], message_id['message_id'], VALID_REACT).text) == {}
    messages = json.loads(get_dm_messages(setup_dm['second_user']['token'], setup_dm['new_dm']['dm_id'], 0).text)
    assert messages['messages'][0]['reacts'] == [{'is_this_user_reacted': False, 'react_id': 1, 'u_ids': [2]}]

    # Test that channel owner can react after a member
    assert json.loads(post_message_react_v1(setup_dm['first_user']['token'], message_id['message_id'], VALID_REACT).text) == {}
    messages = json.loads(get_dm_messages(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], 0).text)
    assert messages['messages'][0]['reacts'] == [{'is_this_user_reacted': True, 'react_id': 1, 'u_ids': [2, 1]}]

#############################################
# message_unreact_v1 Tests
#############################################

# Test input error is raised when message_id is not a valid message within a channel or DM that the authorised user has joined
def test_invalid_message_id_message_unreact_v1_channel(setup):
    second_channel = json.loads(post_channels_create(setup['first_user']['token'], "channel", True).text)
    message_id = json.loads(post_message_send(setup['first_user']['token'], second_channel['channel_id'], NORMAL_MESSAGE).text)
    post_message_react_v1(setup['first_user']['token'], message_id['message_id'], VALID_REACT)
    assert post_message_unreact_v1(setup['second_user']['token'], message_id['message_id'], VALID_REACT).status_code == INPUTERROR
    assert post_message_unreact_v1(setup['second_user']['token'], INVALID_ID, VALID_REACT).status_code == INPUTERROR

def test_invalid_message_id_message_unreact_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    post_message_react_v1(setup_dm['first_user']['token'], message_id['message_id'], VALID_REACT)
    assert post_message_unreact_v1(setup_dm['third_user']['token'], message_id['message_id'], VALID_REACT).status_code == INPUTERROR

# Test input error is raised when react_id is not a valid react ID
def test_invalid_react_id_message_unreact_v1_channel(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    assert post_message_unreact_v1(setup['first_user']['token'], message_id['message_id'], INVALID_REACT).status_code == INPUTERROR

def test_invalid_react_id_message_unreact_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    assert post_message_unreact_v1(setup_dm['first_user']['token'], message_id['message_id'], INVALID_REACT).status_code == INPUTERROR

# Test input error is raised when the message does not contain a react with ID react_id from the authorised user
def test_message_does_not_have_react_message_unreact_v1_channel(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    assert post_message_unreact_v1(setup['first_user']['token'], message_id['message_id'], VALID_REACT).status_code == INPUTERROR

def test_message_does_not_have_react_message_unreact_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    assert post_message_unreact_v1(setup_dm['first_user']['token'], message_id['message_id'], VALID_REACT).status_code == INPUTERROR

# Test access error is raised when an invalid token is given
def test_invalid_token_message_unreact_v1(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    assert post_message_unreact_v1(INVALID_TOKEN, message_id['message_id'], VALID_REACT).status_code == ACCESSERROR

# Test that the function works as expected
def test_valid_message_unreact_v1_channel(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    
    # Test that react has been added succesfully
    assert json.loads(post_message_react_v1(setup['first_user']['token'], message_id['message_id'], VALID_REACT).text) == {}
    messages = json.loads(get_channel_messages(setup['first_user']['token'], setup['new_channel']['channel_id'], 0).text)
    assert messages['messages'][0]['reacts'] == [{'is_this_user_reacted': True, 'react_id': 1, 'u_ids': [1]}]

    # Test that react has been removed successfully
    assert json.loads(post_message_unreact_v1(setup['first_user']['token'], message_id['message_id'], VALID_REACT).text) == {}
    messages = json.loads(get_channel_messages(setup['first_user']['token'], setup['new_channel']['channel_id'], 0).text)
    assert messages['messages'][0]['reacts'] == []


def test_valid_message_unreact_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)

    # Test that react has been added successfully    
    assert json.loads(post_message_react_v1(setup_dm['first_user']['token'], message_id['message_id'], VALID_REACT).text) == {}
    messages = json.loads(get_dm_messages(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], 0).text)
    assert messages['messages'][0]['reacts'] == [{'is_this_user_reacted': True, 'react_id': 1, 'u_ids': [1]}]

    # Test that react has been removed successfully
    assert json.loads(post_message_unreact_v1(setup_dm['first_user']['token'], message_id['message_id'], VALID_REACT).text) == {}
    messages = json.loads(get_dm_messages(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], 0).text)
    assert messages['messages'][0]['reacts'] == []


#############################################
# message_pin_v1 Tests
#############################################

# Test input error is raised when message_id is not a valid message within a channel or DM that the authorised user has joined
def test_invalid_message_id_message_pin_v1_channel(setup):
    second_channel = json.loads(post_channels_create(setup['first_user']['token'], "channel", True).text)
    message_id = json.loads(post_message_send(setup['first_user']['token'], second_channel['channel_id'], NORMAL_MESSAGE).text)
    assert post_message_pin_v1(setup['second_user']['token'], message_id['message_id']).status_code == INPUTERROR

def test_invalid_message_id_message_pin_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    assert post_message_pin_v1(setup_dm['third_user']['token'], message_id['message_id']).status_code == INPUTERROR

# Test input error is raised when the message is already pinned
def test_already_pinned_message_message_pin_v1_channel(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    post_message_pin_v1(setup['first_user']['token'], message_id['message_id'])
    assert post_message_pin_v1(setup['first_user']['token'], message_id['message_id']).status_code == INPUTERROR

def test_already_pinned_message_message_pin_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    post_message_pin_v1(setup_dm['first_user']['token'], message_id['message_id'])
    assert post_message_pin_v1(setup_dm['first_user']['token'], message_id['message_id']).status_code == INPUTERROR

# Test access error is raised when message_id refers to a valid message in a joined channel/DM and the authorised user does not have owner permissions in the channel/DM
def test_unauthorised_user_message_pin_v1_channel(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    post_channel_invite(setup['first_user']['token'], setup['new_channel']['channel_id'], setup['second_user']['auth_user_id'])
    assert post_message_pin_v1(setup['second_user']['token'], message_id['message_id']).status_code == ACCESSERROR

def test_unauthorised_user_message_pin_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    assert post_message_pin_v1(setup_dm['second_user']['token'], message_id['message_id']).status_code == ACCESSERROR

# Test access error is raised when an invalid token is given
def test_invalid_token_message_pin_v1(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    assert post_message_pin_v1(INVALID_TOKEN, message_id['message_id']).status_code == ACCESSERROR

# Test that the message is pinned successfully
def test_valid_message_pin_v1_channel(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    post_message_pin_v1(setup['first_user']['token'], message_id['message_id'])
    messages = json.loads(get_channel_messages(setup['first_user']['token'], setup['new_channel']['channel_id'], 0).text)
    assert messages['messages'][0]['is_pinned'] == True

def test_valid_message_pin_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    post_message_pin_v1(setup_dm['first_user']['token'], message_id['message_id'])
    messages = json.loads(get_dm_messages(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], 0).text)
    assert messages['messages'][0]['is_pinned'] == True

# Check that the message can be unpinned by a global owner
def test_valid_message_pin_v1_global_owner(setup):
    second_channel = json.loads(post_channels_create(setup['second_user']['token'], "second_channel", True).text)
    post_channel_invite(setup['second_user']['token'], second_channel['channel_id'], setup['first_user']['auth_user_id'])
    message_id = json.loads(post_message_send(setup['first_user']['token'], second_channel['channel_id'], NORMAL_MESSAGE).text)
    post_message_pin_v1(setup['first_user']['token'], message_id['message_id'])
    messages = json.loads(get_channel_messages(setup['first_user']['token'], second_channel['channel_id'], 0).text)
    assert messages['messages'][0]['is_pinned'] == True

#############################################
# message_unpin_v1 Tests
#############################################

# Test input error is raised when message_id is not a valid message within a channel or DM that the authorised user has joined
def test_invalid_message_id_message_unpin_v1_channel(setup):
    second_channel = json.loads(post_channels_create(setup['first_user']['token'], "channel", True).text)
    message_id = json.loads(post_message_send(setup['first_user']['token'], second_channel['channel_id'], NORMAL_MESSAGE).text)
    assert post_message_unpin_v1(setup['second_user']['token'], message_id['message_id']).status_code == INPUTERROR

def test_invalid_message_id_message_unpin_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    assert post_message_unpin_v1(setup_dm['third_user']['token'], message_id['message_id']).status_code == INPUTERROR

# Test input error is raised when the message is not already pinned
def test_message_not_pinned_message_unpin_v1_channel(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    assert post_message_unpin_v1(setup['first_user']['token'], message_id['message_id']).status_code == INPUTERROR

def test_message_not_pinned_message_unpin_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    assert post_message_unpin_v1(setup_dm['first_user']['token'], message_id['message_id']).status_code == INPUTERROR

# Test access error is raised when message_id refers to a valid message in a joined channel/DM and the authorised user does not have owner permissions in the channel/DM
def test_unauthorised_user_message_unpin_v1_channel(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    post_message_pin_v1(setup['first_user']['token'], message_id['message_id'])
    post_channel_invite(setup['first_user']['token'], setup['new_channel']['channel_id'], setup['second_user']['auth_user_id'])
    assert post_message_unpin_v1(setup['second_user']['token'], message_id['message_id']).status_code == ACCESSERROR

def test_unauthorised_user_message_unpin_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    post_message_pin_v1(setup_dm['first_user']['token'], message_id['message_id'])
    assert post_message_unpin_v1(setup_dm['second_user']['token'], message_id['message_id']).status_code == ACCESSERROR

# Test access error is raised when an invalid token is given
def test_invalid_token_message_unpin_v1(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    post_message_pin_v1(setup['first_user']['token'], message_id['message_id']).status_code == ACCESSERROR
    assert post_message_unpin_v1(INVALID_TOKEN, message_id['message_id']).status_code == ACCESSERROR

# Test that pinned message is successfully unpinned
def test_valid_message_unpin_v1_channel(setup):
    message_id = json.loads(post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], NORMAL_MESSAGE).text)
    post_message_pin_v1(setup['first_user']['token'], message_id['message_id'])
    messages = json.loads(get_channel_messages(setup['first_user']['token'], setup['new_channel']['channel_id'], 0).text)
    assert messages['messages'][0]['is_pinned'] == True
    post_message_unpin_v1(setup['first_user']['token'], message_id['message_id'])
    messages = json.loads(get_channel_messages(setup['first_user']['token'], setup['new_channel']['channel_id'], 0).text)
    assert messages['messages'][0]['is_pinned'] == False
    
def test_valid_message_unpin_v1_dm(setup_dm):
    message_id = json.loads(post_message_senddm(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], NORMAL_MESSAGE).text)
    post_message_pin_v1(setup_dm['first_user']['token'], message_id['message_id'])
    messages = json.loads(get_dm_messages(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], 0).text)
    assert messages['messages'][0]['is_pinned'] == True
    post_message_unpin_v1(setup_dm['first_user']['token'], message_id['message_id'])
    messages = json.loads(get_dm_messages(setup_dm['first_user']['token'], setup_dm['new_dm']['dm_id'], 0).text)
    assert messages['messages'][0]['is_pinned'] == False

# Test that message can be unpinned by a global owner
def test_valid_message_unpin_v1_global_owner(setup):
    second_channel = json.loads(post_channels_create(setup['second_user']['token'], "second_channel", True).text)
    post_channel_invite(setup['second_user']['token'], second_channel['channel_id'], setup['first_user']['auth_user_id'])
    message_id = json.loads(post_message_send(setup['first_user']['token'], second_channel['channel_id'], NORMAL_MESSAGE).text)
    post_message_unpin_v1(setup['first_user']['token'], message_id['message_id'])
    messages = json.loads(get_channel_messages(setup['first_user']['token'], second_channel['channel_id'], 0).text)
    assert messages['messages'][0]['is_pinned'] == False
