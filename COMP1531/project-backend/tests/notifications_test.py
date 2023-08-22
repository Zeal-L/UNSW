#Imports
import pytest
import requests
import json
from hypothesis import given, strategies, Verbosity, settings
from src import config
from src.helper import generate_jwt, user_from_token

# Constants and Global Variables
INVALID_ID = -1
INVALID_SESSION = -1
INVALID_TOKEN = generate_jwt(INVALID_ID, INVALID_SESSION)
ACCESS_ERROR = 403
INPUT_ERROR = 400
SUCCESS = 200
MESSAGE = "Hello World!"

#Setup Function(s)
@pytest.fixture(scope='function')
def setup():
    # Just create some users here, the channels and dms will be created in the tests to test the notifications
    requests.delete(config.url + "clear/v1")
    requests.post(config.url + "auth/register/v2", json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password', 'name_first' : 'Test User', 'name_last' : '1'})
    requests.post(config.url + "auth/register/v2", json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password', 'name_first' : 'Test User', 'name_last' : '2'})
    requests.post(config.url + "auth/register/v2", json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password', 'name_first' : 'Test User', 'name_last' : '3'})
    requests.post(config.url + "auth/register/v2", json={'email' : 'testuser4@gmail.com', 'password' : 'testuser4password', 'name_first' : 'Test User', 'name_last' : '4'})

    login1_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password'})
    login2_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password'})
    login3_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password'})
    login4_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser4@gmail.com', 'password' : 'testuser4password'})


    login1_result = login1_response.json()
    login2_result = login2_response.json()
    login3_result = login3_response.json()
    login4_result = login4_response.json()
    return [login1_result['token'], login2_result['token'], login3_result['token'], login4_result['token']]


# Tests

def test_invalid_token(setup):
    notification_response = requests.get(config.url + 'notifications/get/v1', params={'token' : INVALID_TOKEN})
    assert notification_response.status_code == ACCESS_ERROR


def test_no_notifications(setup):
    for token in setup:
        notification_response = requests.get(config.url + 'notifications/get/v1', params={'token' : token})
        notifications = notification_response.json()
        assert notifications == {'notifications' : []}

def test_channel_tagged(setup):
    # User 1 create a channel and add users 2,3 and 4
    create_channel_response = requests.post(config.url + 'channels/create/v2', json={'token' : setup[0], 'name' : "Test Channel 1", 'is_public' : True})
    channel_id = create_channel_response.json()
    target_users = setup[1 : ]
    for user in target_users:
        id = user_from_token(user)
        requests.post(config.url + "channel/invite/v2", json={'token' : setup[0], 'channel_id' : channel_id['channel_id'], 'u_id' : id})
    # User 1 send a message, tagging users 2, 3 and 4
    message = "Hello @testuser2, @testuser3, @testuser4"
    message_response = requests.post(config.url + 'message/send/v1', json={'token' : setup[0], 'channel_id' : channel_id['channel_id'], 'message' : message})
    assert message_response.status_code == SUCCESS

    # then get the notifcations of all four users
    notifications_response = requests.get(config.url + 'notifications/get/v1', params={'token' : setup[0]})
    notifications = notifications_response.json()
    assert notifications == {'notifications' : []}
    for user in target_users:
        notifications_response = requests.get(config.url + 'notifications/get/v1', params={'token' : user})
        notifications = notifications_response.json()
        assert notifications == {
            'notifications' : [
                {
                    'channel_id' : channel_id['channel_id'],
                    'dm_id' : -1,
                    'notification_message' : 'testuser1 tagged you in Test Channel 1: ' + message[ :21] 
                },
                {
                    'channel_id' : channel_id['channel_id'],
                    'dm_id' : -1,
                    'notification_message' : 'testuser1 added you to Test Channel 1'
                }
            ]
        }

def test_dm_tagged(setup):
   # User 1 create a dm and add users 2,3 and 4
    create_dm_response = requests.post(config.url + 'dm/create/v1', json={'token' : setup[0], 'u_ids' : [2,3,4]})
    dm_id = create_dm_response.json()
    target_users = setup[1 : ]
    # User 1 send a message, tagging users 2, 3 and 4
    message = "Hello @testuser2, @testuser3, @testuser4"
    message_response = requests.post(config.url + 'message/senddm/v1', json={'token' : setup[0], 'dm_id' : dm_id['dm_id'], 'message' : message})
    assert message_response.status_code == SUCCESS

    # then get the notifcations of all four users
    notifications_response = requests.get(config.url + 'notifications/get/v1', params={'token' : setup[0]})
    notifications = notifications_response.json()

    assert notifications == {'notifications' : []}
    for user in target_users:
        notifications_response = requests.get(config.url + 'notifications/get/v1', params={'token' : user})
        notifications = notifications_response.json()
        assert notifications == {
            'notifications' : [
                {
                    'channel_id' : -1,
                    'dm_id' : dm_id['dm_id'],
                    'notification_message' : 'testuser1 tagged you in testuser1, testuser2, testuser3, testuser4: ' + message[ :21] 
                },
                {
                    'channel_id' : -1,
                    'dm_id' : dm_id['dm_id'],
                    'notification_message' : 'testuser1 added you to testuser1, testuser2, testuser3, testuser4'
                }
            ]
        }


def test_channel_react(setup):
    # create a channel, add members, send a message, react to it then get the notifcations
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup[0], 'name' : 'Test Channel 1', 'is_public' : True})
    c_id = channel_create.json()

    tokens = setup[1:]
    for token in tokens:
        requests.post(config.url + 'channel/join/v2', json={'token' : token, 'channel_id' : c_id['channel_id']})
    
    message_send = requests.post(config.url + 'message/send/v1', json={'token' : setup[0], 'channel_id' : c_id['channel_id'], 'message' : MESSAGE})
    m_id = message_send.json()
    
    for token in tokens:
        react = requests.post(config.url + 'message/react/v1', json={'token' : token, 'message_id' : m_id['message_id'], 'react_id' : 1})
        assert react.status_code == SUCCESS
    notifications_response = requests.get(config.url + 'notifications/get/v1', params={'token' : setup[0]})
    notifications = notifications_response.json()
    assert len(notifications['notifications']) == 3
    assert notifications == {'notifications' : 
        [
                {
                    'channel_id' : c_id['channel_id'],
                    'dm_id' : -1,
                    'notification_message' : 'testuser4 reacted to your message in Test Channel 1' 
                },
                {
                    'channel_id' : c_id['channel_id'],
                    'dm_id' : -1,
                    'notification_message' : 'testuser3 reacted to your message in Test Channel 1' 
                },
                {
                    'channel_id' : c_id['channel_id'],
                    'dm_id' : -1,
                    'notification_message' : 'testuser2 reacted to your message in Test Channel 1'
                }
        ]
    }
def test_dm_react(setup):
    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup[0], 'u_ids' : [2,3,4]})
    dm_id = dm_create.json()
    
    message_send = requests.post(config.url + 'message/senddm/v1', json={'token' : setup[0], 'dm_id' : dm_id['dm_id'], 'message' : MESSAGE})
    m_id = message_send.json()
    tokens = setup[1:]
    for token in tokens:
        requests.post(config.url + 'message/react/v1', json={'token' : token, 'message_id' : m_id['message_id'], 'react_id' : 1})
    notifications_response = requests.get(config.url + 'notifications/get/v1', params={'token' : setup[0]})
    notifications = notifications_response.json()
    assert len(notifications['notifications']) == 3
    assert notifications == {'notifications' : 
        [
            {
                'channel_id' : -1,
                'dm_id' : dm_id['dm_id'],
                'notification_message' : 'testuser4 reacted to your message in testuser1, testuser2, testuser3, testuser4' 
            },
            {
                'channel_id' : -1,
                'dm_id' : dm_id['dm_id'],
                'notification_message' : 'testuser3 reacted to your message in testuser1, testuser2, testuser3, testuser4' 
            },
            {
                'channel_id' : -1,
                'dm_id' : dm_id['dm_id'],
                'notification_message' : 'testuser2 reacted to your message in testuser1, testuser2, testuser3, testuser4'
            }
        ]
    }
def test_channel_added(setup):
    # User 1 create a channel and add users 2,3 and 4
    create_channel_response = requests.post(config.url + 'channels/create/v2', json={'token' : setup[0], 'name' : "Test Channel 1", 'is_public' : True})
    channel_id = create_channel_response.json()
    target_users = setup[1 : ]
    for user in target_users:
        id = user_from_token(user)
        requests.post(config.url + "channel/invite/v2", json={'token' : setup[0], 'channel_id' : channel_id['channel_id'], 'u_id' : id})
    # then get the notifcations of all four users
    notifications_response = requests.get(config.url + 'notifications/get/v1', params={'token' : setup[0]})
    notifications = notifications_response.json()
    assert notifications == {'notifications' : []}
    for user in target_users:
        notifications_response = requests.get(config.url + 'notifications/get/v1', params={'token' : user})
        notifications = notifications_response.json()
        assert notifications == {
            'notifications' : [
                {
                    'channel_id' : channel_id['channel_id'],
                    'dm_id' : -1,
                    'notification_message' : 'testuser1 added you to Test Channel 1'
                }
            ]
        }

def test_dm_added(setup):
   # User 1 create a dm and add users 2,3 and 4
    create_dm_response = requests.post(config.url + 'dm/create/v1', json={'token' : setup[0], 'u_ids' : [2,3,4]})
    dm_id = create_dm_response.json()
    target_users = setup[1 : ]

    # then get the notifcations of all four users
    notifications_response = requests.get(config.url + 'notifications/get/v1', params={'token' : setup[0]})
    notifications = notifications_response.json()

    assert notifications == {'notifications' : []}
    for user in target_users:
        notifications_response = requests.get(config.url + 'notifications/get/v1', params={'token' : user})
        notifications = notifications_response.json()
        assert notifications == {
            'notifications' : [
                {
                    'channel_id' : -1,
                    'dm_id' : dm_id['dm_id'],
                    'notification_message' : 'testuser1 added you to testuser1, testuser2, testuser3, testuser4'
                }
            ]
        }

def test_multiples_of_20(setup):
    # User 1 create a channel and add users 2,3 and 4
    create_channel_response = requests.post(config.url + 'channels/create/v2', json={'token' : setup[0], 'name' : "Test Channel 1", 'is_public' : True})
    channel_id = create_channel_response.json()
    target_users = setup[1 : ]
    for user in target_users:
        id = user_from_token(user)
        requests.post(config.url + "channel/invite/v2", json={'token' : setup[0], 'channel_id' : channel_id['channel_id'], 'u_id' : id})    
    
    for dummy_i in range(21):
        message = "Hello @testuser2, @testuser3, @testuser4"
        message_response = requests.post(config.url + 'message/send/v1', json={'token' : setup[0], 'channel_id' : channel_id['channel_id'], 'message' : message})
        assert message_response.status_code == SUCCESS
    # 21 notifications in total, show the 20 most recent
    for u in target_users:
        notifications_response = requests.get(config.url + 'notifications/get/v1', params={'token' : u})
        notifications = notifications_response.json()
        notification = {'channel_id' : channel_id['channel_id'], 'dm_id' : -1, 'notification_message' : 'testuser1 tagged you in Test Channel 1: ' + message[ :21] }
        assert notifications == {
            'notifications' : [notification] * 20
        }
