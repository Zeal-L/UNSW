# Imports
import pytest
import requests
import json
from datetime import datetime
from src import config
from src.helper import generate_jwt

# Global Constants
INVALID_ID = -1
INVALID_TOKEN = generate_jwt(INVALID_ID, 0)

# Setup Functions

# Setup function to register multiple users and have one login
@pytest.fixture(scope='function')
def setup1():
    # Reset the data store
    requests.delete(config.url + 'clear/v1')

    # Register a test user and log them in to create a token
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password', 'name_first' : "Test User", 'name_last' : "1"})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password', 'name_first' : "Test User", 'name_last' : "2"})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password', 'name_first' : "Test User", 'name_last' : "3"})
    login_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password'})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password', 'name_first' : "Test User", 'name_last' : "3"})
    token_data = login_response.json()
    return token_data['token']

# Setup function to register multiple users and have them all login
@pytest.fixture(scope='function')
def setup2():
    # Reset the data store
    requests.delete(config.url + 'clear/v1')

    # Register a test user and log them in to create a token
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password', 'name_first' : "Test User", 'name_last' : "1"})
    login_response = requests.post(config.url + 'auth/login/v2', json={ 'email' : 'testuser1@gmail.com', 'password' : 'testuser1password'})
    user1_token = login_response.json()

    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password', 'name_first' : "Test User", 'name_last' : "2"})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password', 'name_first' : "Test User", 'name_last' : "3"})

    login_response = requests.post(config.url + 'auth/login/v2', json={ 'email' : 'testuser2@gmail.com', 'password' : 'testuser2password'})
    user2_token = login_response.json()
    login_response = requests.post(config.url + 'auth/login/v2', json={ 'email' : 'testuser3@gmail.com', 'password' : 'testuser3password'})
    user3_token = login_response.json()

    return [user1_token['token'], user2_token['token'], user3_token['token']]

# Setup function to have multiple users register, all login and create one dm
@pytest.fixture(scope='function')
def setup3():
    # Reset the data store
    requests.delete(config.url + 'clear/v1')

    # Register a test user and log them in to create a token
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password', 'name_first' : "Test User", 'name_last' : "1"})
    login_response = requests.post(config.url + 'auth/login/v2', json={ 'email' : 'testuser1@gmail.com', 'password' : 'testuser1password'})
    user1_token = login_response.json()

    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password', 'name_first' : "Test User", 'name_last' : "2"})
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password', 'name_first' : "Test User", 'name_last' : "3"})
    login2_response = requests.post(config.url + 'auth/login/v2', json={ 'email' : 'testuser2@gmail.com', 'password' : 'testuser2password'})
    login3_response = requests.post(config.url + 'auth/login/v2', json={ 'email' : 'testuser3@gmail.com', 'password' : 'testuser3password'})
    user2_token = login2_response.json()
    user3_token = login3_response.json()

    requests.post(config.url + "dm/create/v1", json={'token' : user1_token['token'], 'u_ids' : [2,3]})

    return [user1_token['token'], user2_token['token'], user3_token['token']]

# Tests

# Tests for dm/create/v1

def test_invalid_user(setup1):
    # A u_id in the list passed into the function does not refer to a valid user.
    # This will raise an input error (code 403)
    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup1, 'u_ids' : [-1]})
    assert dm_create.status_code == 400
    dm_create_2 = requests.post(config.url + 'dm/create/v1', json={'token' : setup1, 'u_ids' : [-2, -1, 0, 1, 2]})
    assert dm_create_2.status_code == 400

def test_invalid_token(setup1):
    # The token passed into the function is invalid. This should raise an access error (code 400)

    dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : INVALID_TOKEN, 'u_ids' : [2]})
    assert dm_create.status_code == 403

def test_dm_owner(setup1):
    dm_create = requests.post(config.url + "dm/create/v1", json={'token' : setup1, 'u_ids' : [2]})
    result = dm_create.json()
    assert result == {'dm_id' : 0}

def test_dm_one_user(setup1):
    dm_create = requests.post(config.url + "dm/create/v1", json={'token' : setup1, 'u_ids' : [2]})
    result = dm_create.json()
    assert result == {'dm_id' : 0}

def test_dm_multiple_users(setup1):
    dm_create = requests.post(config.url + "dm/create/v1", json={'token' : setup1, 'u_ids' : [2,3]})
    result = dm_create.json()
    assert result == {'dm_id' : 0}

def test_create_multiple_dms(setup1):
    for i in range(2):
        dm_create = requests.post(config.url + "dm/create/v1", json={'token' : setup1, 'u_ids' : [2,3]})
        result = dm_create.json()
        assert result == {'dm_id' : i}

# Tests for dm/details/v1

# Invalid token, valid dm_id - testing general access error
def test_invalid_token_valid_id_d(setup2):
    create_response = requests.post(config.url + "dm/create/v1", json={'token' : setup2[0], 'u_ids' : [2,3]})
    id = create_response.json()
    details_response = requests.get(config.url + "dm/details/v1", params={'token' : INVALID_TOKEN, 'dm_id' : id['dm_id']})
    assert details_response.status_code == 403

# Valid token, invalid dm_id - testing input error
def test_valid_token_invalid_id_d(setup2):
    requests.post(config.url + "dm/create/v1", json={'token' : setup2[0], 'u_ids' : [2,3]})
    details_response = requests.get(config.url + "dm/details/v1", params={'token' : setup2[0], 'dm_id' : INVALID_ID})
    assert details_response.status_code == 400

# Valid token - but not member, valid dm_id
def test_not_member_valid_id_d(setup2):
    create_response = requests.post(config.url + "dm/create/v1", json={'token' : setup2[0], 'u_ids' : []})
    id = create_response.json()
    details_response = requests.get(config.url + "dm/details/v1", params={'token' : setup2[2], 'dm_id' : id['dm_id']})
    assert details_response.status_code == 403

# Valid token - is member, valid dm_id
def test_is_member_valid_id_d(setup2):
    create_response = requests.post(config.url + "dm/create/v1", json={'token' : setup2[0], 'u_ids' : [2,3]})
    id = create_response.json()
    details_response = requests.get(config.url + "dm/details/v1", params={'token' : setup2[0], 'dm_id' : id['dm_id']})
    details_result = details_response.json()
    # Get the list of members and dm name
    assert details_result == {
        'name' : 'testuser1, testuser2, testuser3',
        'members' : [
            {
                'u_id' : 1,
                'email' : 'testuser1@gmail.com',
                'name_first' : 'Test User',
                'name_last' : '1',
                'handle_str': 'testuser1',
                'profile_img_url': None
            },
            {
                'u_id' : 2,
                'email' : 'testuser2@gmail.com',
                'name_first' : 'Test User',
                'name_last' : '2',
                'handle_str': 'testuser2',
                'profile_img_url': None
            },
            {
                'u_id' : 3,
                'email' : 'testuser3@gmail.com',
                'name_first' : 'Test User',
                'name_last' : '3',
                'handle_str': 'testuser3',
                'profile_img_url': None
            }
        ]
    }

    details_response_2 = requests.get(config.url + "dm/details/v1", params={'token' : setup2[1], 'dm_id' : id['dm_id']})
    details_result_2 = details_response_2.json()
    # Get the list of members and dm name
    assert details_result_2 == {
        'name' : 'testuser1, testuser2, testuser3',
        'members' : [
            {
                'u_id' : 1,
                'email' : 'testuser1@gmail.com',
                'name_first' : 'Test User',
                'name_last' : '1',
                'handle_str': 'testuser1',
                'profile_img_url': None
            },
            {
                'u_id' : 2,
                'email' : 'testuser2@gmail.com',
                'name_first' : 'Test User',
                'name_last' : '2',
                'handle_str': 'testuser2',
                'profile_img_url': None
            },
            {
                'u_id' : 3,
                'email' : 'testuser3@gmail.com',
                'name_first' : 'Test User',
                'name_last' : '3',
                'handle_str': 'testuser3',
                'profile_img_url': None
            }
        ]
    }

    details_response_3 = requests.get(config.url + "dm/details/v1", params={'token' : setup2[2], 'dm_id' : id['dm_id']})
    details_result_3 = details_response_3.json()
    # Get the list of members and dm name
    assert details_result_3 == {
        'name' : 'testuser1, testuser2, testuser3',
        'members' : [
            {
                'u_id' : 1,
                'email' : 'testuser1@gmail.com',
                'name_first' : 'Test User',
                'name_last' : '1',
                'handle_str': 'testuser1',
                'profile_img_url': None
            },
            {
                'u_id' : 2,
                'email' : 'testuser2@gmail.com',
                'name_first' : 'Test User',
                'name_last' : '2',
                'handle_str': 'testuser2',
                'profile_img_url': None
            },
            {
                'u_id' : 3,
                'email' : 'testuser3@gmail.com',
                'name_first' : 'Test User',
                'name_last' : '3',
                'handle_str': 'testuser3',
                'profile_img_url': None
            }
        ]
    }


# Tests for dm/list/v1

def test_invalid_token_l():
    list_response = requests.get(config.url + 'dm/list/v1', params={'token' : INVALID_TOKEN})
    assert list_response.status_code == 403

# No DMs have been created
def test_no_dms_l(setup2):
    list_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[0]})
    results = list_response.json()
    assert results == {'dms' : []}

# One DM has been created and joined by Test User 2 and 3
def test_one_dm(setup2):
    requests.post(config.url + "dm/create/v1", json={'token': setup2[0], "u_ids" : [2,3]})
    owner_list_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[0]})
    owner_list_results = owner_list_response.json()
    assert owner_list_results == {'dms' : [
        {
            'dm_id' : 0,
            'name' : "testuser1, testuser2, testuser3"
        }
    ]}

    user_2_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[1]})
    user_2_results = user_2_response.json()
    assert user_2_results == {'dms' : [
        {
            'dm_id' : 0,
            'name' : "testuser1, testuser2, testuser3" # need to get the name
        }
    ]}

    user_3_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[2]})
    user_3_results = user_3_response.json()
    assert user_3_results == {'dms' : [
        {
            'dm_id' : 0,
            'name' : "testuser1, testuser2, testuser3"
        }
    ]}

# Multiple DMs created and all are joined by Test User 2 and 3
def test_multiple_dms_all_joined_l(setup2):
    for i in range(3):
        create_response = requests.post(config.url + "dm/create/v1", json={'token': setup2[0], "u_ids" : [2,3]})
        id = create_response.json()
        assert id['dm_id'] == i
    owner_list_response = requests.get(config.url + "dm/list/v1", params={'token' : setup2[0]})
    owner_list_results = owner_list_response.json()
    assert owner_list_results == {'dms' : [
        {
            'dm_id' : 0,
            'name' : 'testuser1, testuser2, testuser3'
        },
        {
            'dm_id' : 1,
            'name' : 'testuser1, testuser2, testuser3'
        },
        {
            'dm_id' : 2,
            'name' : 'testuser1, testuser2, testuser3'
        }
    ]}

    user_2_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[1]})
    user_2_results = user_2_response.json()
    assert user_2_results == {'dms' : [
        {
            'dm_id' : 0,
            'name' : 'testuser1, testuser2, testuser3'
        },
        {
            'dm_id' : 1,
            'name' : 'testuser1, testuser2, testuser3'
        },
        {
            'dm_id' : 2,
            'name' : 'testuser1, testuser2, testuser3'
        }
    ]}

    user_3_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[2]})
    user_3_results = user_3_response.json()
    assert user_3_results == {'dms' : [
        {
            'dm_id' : 0,
            'name' : 'testuser1, testuser2, testuser3'
        },
        {
            'dm_id' : 1,
            'name' : 'testuser1, testuser2, testuser3'
        },
        {
            'dm_id' : 2,
            'name' : 'testuser1, testuser2, testuser3'
        }
    ]}

# Multiple DMs created, all are joined by Test User 2, some are joined by 3
def test_multiple_dms_some_joined_l(setup2):
    for i in range(3):
        if i == 0:
            requests.post(config.url + "dm/create/v1", json={'token': setup2[0], "u_ids" : [2,3]})
        else:
            requests.post(config.url + "dm/create/v1", json={'token' : setup2[0], "u_ids" : [2]})

    owner_list_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[0]})
    owner_list_results = owner_list_response.json()
    assert owner_list_results == {'dms' : [
        {
            'dm_id' : 0,
            'name' : 'testuser1, testuser2, testuser3'
        },
        {
            'dm_id' : 1,
            'name' : 'testuser1, testuser2'
        },
        {
            'dm_id' : 2,
            'name' : 'testuser1, testuser2'
        }
    ]}

    user_2_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[1]})
    user_2_results = user_2_response.json()
    assert user_2_results == {'dms' : [
        {
            'dm_id' : 0,
            'name' : 'testuser1, testuser2, testuser3'
        },
        {
            'dm_id' : 1,
            'name' : 'testuser1, testuser2'
        },
        {
            'dm_id' : 2,
            'name' : 'testuser1, testuser2'
        }
    ]}

    user_3_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[2]})
    user_3_results = user_3_response.json()
    assert user_3_results == {'dms' : [
        {
            'dm_id' : 0,
            'name' : 'testuser1, testuser2, testuser3'
        }
    ]}

# Multiple DMs created, none are joined by Test User 3
def test_no_dms_joined(setup2):
    for i in range(3):
        create_response = requests.post(config.url + "dm/create/v1", json={'token' : setup2[0], "u_ids" : [2]})
        id = create_response.json()
        assert id['dm_id'] == i

    owner_list_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[0]})
    owner_list_results = owner_list_response.json()
    assert owner_list_results == {'dms' : [
        {
            'dm_id' : 0,
            'name' : 'testuser1, testuser2'
        },
        {
            'dm_id' : 1,
            'name' : 'testuser1, testuser2'
        },
        {
            'dm_id' : 2,
            'name' : 'testuser1, testuser2'
        }
    ]}

    user_2_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[1]})
    user_2_results = user_2_response.json()
    assert user_2_results == {'dms' : [
        {
            'dm_id' : 0,
            'name' : 'testuser1, testuser2'
        },
        {
            'dm_id' : 1,
            'name' : 'testuser1, testuser2'
        },
        {
            'dm_id' : 2,
            'name' : 'testuser1, testuser2'
        }
    ]}

    user_3_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[2]})
    user_3_results = user_3_response.json()
    assert user_3_results == {'dms' : []}



# Tests for dm/remove/v1
def test_invalid_token_valid_id_r(setup2):
    create_response = requests.post(config.url + "dm/create/v1", json={'token' : setup2[0], 'u_ids' : [2,3]})
    id = create_response.json()
    remove_response = requests.delete(config.url + "dm/remove/v1", json={'token' : INVALID_TOKEN, 'dm_id' : id['dm_id']})
    assert remove_response.status_code == 403

# Valid token, invalid dm id
def test_valid_token_invalid_id_r(setup2):
    requests.post(config.url + "dm/create/v1", json={'token' : setup2[0], 'u_ids' : [2,3]})
    remove_response = requests.delete(config.url + "dm/remove/v1", json={'token' : setup2[0], 'dm_id' : INVALID_ID})
    assert remove_response.status_code == 400

# Valid token, valid dm id, token does not refer to the original creator
def test_valid_token_not_creator_r(setup2):
    create_response = requests.post(config.url + "dm/create/v1", json={'token' : setup2[0], 'u_ids' : [2,3]})
    id = create_response.json()
    remove_response = requests.delete(config.url + "dm/remove/v1", json={'token' : setup2[1], 'dm_id' : id['dm_id']})
    assert remove_response.status_code == 403

# Valid token, valid dm id and token refers to original creator
def test_remove_as_creator_r(setup2):
    create_response = requests.post(config.url + "dm/create/v1", json={'token' : setup2[0], 'u_ids' : [2,3]})
    id = create_response.json()
    requests.delete(config.url + "dm/remove/v1", json={'token' : setup2[0], 'dm_id' : id['dm_id']})

    list_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[0]})
    list_result = list_response.json()
    assert len(list_result['dms']) == 0

    details_response = requests.get(config.url + "dm/details/v1", params={'token' : setup2[0], 'dm_id' : id['dm_id']})
    assert details_response.status_code == 403

# Remove multiple dms
def test_remove_multiple_as_creator_r(setup2):
    for i in range(3):
        create_response = requests.post(config.url + "dm/create/v1", json={'token' : setup2[0], 'u_ids' : [2,3]})
        id = create_response.json()
        assert id['dm_id'] == i

    remove_response = requests.delete(config.url + "dm/remove/v1", json={'token' : setup2[0], 'dm_id' : 0})
    remove_result = remove_response.json()
    assert remove_response.status_code == 200
    assert remove_result == {}

    list_response = requests.get(config.url + 'dm/list/v1', params={'token' : setup2[0]})
    list_result = list_response.json()
    assert len(list_result['dms']) == 2
    assert list_result == {'dms' : [
        {
            'dm_id' : 1,
            'name' : 'testuser1, testuser2, testuser3'
        },
        {
            'dm_id' : 2,
            'name' : 'testuser1, testuser2, testuser3'
        }
    ]}

    details_response = requests.get(config.url + "dm/details/v1", params={'token' : setup2[0], 'dm_id' : 0})
    assert details_response.status_code == 403
    details_response_2 = requests.get(config.url + "dm/details/v1", params={'token' : setup2[0], 'dm_id' : 1})
    details_result = details_response_2.json()
    assert details_result == {
        'name' : 'testuser1, testuser2, testuser3',
        'members' : [
            {
                'u_id' : 1,
                'email' : 'testuser1@gmail.com',
                'name_first' : 'Test User',
                'name_last' : '1',
                'handle_str': 'testuser1',
                'profile_img_url': None
            },
            {
                'u_id' : 2,
                'email' : 'testuser2@gmail.com',
                'name_first' : 'Test User',
                'name_last' : '2',
                'handle_str': 'testuser2',
                'profile_img_url': None
            },
            {
                'u_id' : 3,
                'email' : 'testuser3@gmail.com',
                'name_first' : 'Test User',
                'name_last' : '3',
                'handle_str': 'testuser3',
                'profile_img_url': None
            }
        ]
    }

# Tests for dm/leave/v1

# Invalid token but a valid dm_id
def test_invalid_token_valid_id_leave(setup2):
    # Create a dm, attempt to leave it with an invalid token
    create_response = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3]})
    id = create_response.json()
    leave_response = requests.post(config.url + "dm/leave/v1", json={'token' : INVALID_TOKEN, 'dm_id' : id['dm_id']})
    assert leave_response.status_code == 403

# Valid token but an invalid dm id
def test_valid_token_invalid_id_leave(setup2):
    # Create a dnm attempt to leave a dm with INVALID_ID
    requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3]})
    leave_response = requests.post(config.url + "dm/leave/v1", json={'token' : setup2[0], 'dm_id' : INVALID_ID})
    assert leave_response.status_code == 400

# Valid token and valid dm id but the user is not a member of the dm
def test_not_member_leave(setup2):
    # Create a dm and attempt to leave it as a non-member
    create_response = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2]})
    id = create_response.json()
    leave_response = requests.post(config.url + "dm/leave/v1", json={'token' : setup2[2], 'dm_id' : id['dm_id']})
    assert leave_response.status_code == 403

# Valid token and dm id and the user is a member of the dm
def test_is_member_leave(setup2):
    # Create a dm and attempt to leave it with each user in setup1
    create_response = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3]})
    id = create_response.json()
    leave_response = requests.post(config.url + "dm/leave/v1", json={'token' : setup2[1], 'dm_id' : id['dm_id']})
    assert leave_response.status_code == 200
    leave_response_2 = requests.post(config.url + "dm/leave/v1", json={'token' : setup2[2], "dm_id" : id['dm_id']})
    assert leave_response_2.status_code == 200

# Valid token and dm id and the user is a member of the dm, owner leave case
def test_is_member_owner_leave(setup2):
    # Create a dm and attempt to leave it with each user in setup1
    create_response = requests.post(config.url + 'dm/create/v1', json={'token' : setup2[0], 'u_ids' : [2,3]})
    id = create_response.json()
    leave_response = requests.post(config.url + "dm/leave/v1", json={'token' : setup2[0], 'dm_id' : id['dm_id']})
    assert leave_response.status_code == 200




# Tests for dm/messages/v1

# Invalid token, valid dm id, valid start value
def test_invalid_token_m(setup3):
    message_response = requests.get(config.url + 'dm/messages/v1', params={'token' : INVALID_TOKEN, 'dm_id' : 0, 'start' : 0})
    assert message_response.status_code ==  403


# Valid token, invalid dm id, valid start
def test_invalid_dm_id_m(setup3):
    message_response = requests.get(config.url + 'dm/messages/v1', params={'token' : setup3[0], 'dm_id' : INVALID_ID, 'start' : 0})
    assert message_response.status_code == 400


# Valid token, valid dm id, invalid start
def test_invalid_start_index_m(setup3):
    message_response = requests.get(config.url + 'dm/messages/v1', params={'token' : setup3[0], 'dm_id' : 0, 'start' : 50})
    assert message_response.status_code == 400


# Valid token but not a member, valid dm_id, valid start
def test_not_member_m(setup3):
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser4@gmail.com', 'password' : 'testuser4password', 'name_first' : "Test User", 'name_last' : "4"})
    user4_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser4@gmail.com', 'password' : 'testuser4password'})
    user4_token = user4_response.json()
    message_response = requests.get(config.url  + 'dm/messages/v1', params={'token' : user4_token['token'], 'dm_id' : 0, 'start' : 0})
    assert message_response.status_code == 403

# Listing 0 messages
def test_list_no_messages_m(setup3):
    message_response = requests.get(config.url  + 'dm/messages/v1', params={'token' : setup3[0], 'dm_id' : 0, 'start' : 0})
    message_list = message_response.json()
    assert message_list == {'messages' : [], 'start' : 0, 'end' : -1}

# Listing 1 message
def test_list_one_message_m(setup3):
    requests.post(config.url + "message/senddm/v1", json={'token' : setup3[0], 'dm_id' : 0, 'message' : 'Hello World'})
    time = datetime.now().strftime('%d/%m/%Y, %H:%M:%S')

    message_list_response = requests.get(config.url + 'dm/messages/v1', params={'token' :  setup3[0], 'dm_id' : 0, 'start' : 0})
    message_list_result = message_list_response.json()
    assert message_list_result == {'messages' : [{'message_id' : 0, 'u_id' : 1, 'message' : 'Hello World', 'time_created' : time, 'is_pinned': False, 'reacts': []}], 'start' : 0, 'end' : -1}



# Listing 51 messages
def test_list_more_than_50_messages_m(setup3):
    for i in range(51):
        message_response = requests.post(config.url + 'message/senddm/v1', json={'token' : setup3[0], 'dm_id' : 0, 'message' : 'Hello World'})
        message_id = message_response.json()
        assert message_id['message_id'] == i
    message_list_response = requests.get(config.url + 'dm/messages/v1', params={'token' : setup3[0], 'dm_id' : 0, 'start' : 0})
    message_list_result = message_list_response.json()
    assert message_list_result['start'] == 0
    assert message_list_result['end'] == 50
    assert len(message_list_result['messages']) == 50
