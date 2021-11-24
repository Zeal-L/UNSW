#############################################
# Import(s)
#############################################

import pytest
import requests
import json
from src import config
import tests.requests as re
from datetime import datetime, timezone
from PIL import Image, ImageChops
from io import BytesIO
from urllib import request

MESSAGE = 'Hello World!'
INPUTERROR = 400
ACCESSERROR = 403

#############################################
# Initial setup (Reset state of application)
#############################################

@pytest.fixture(scope="function")
def setup():
    requests.delete(config.url + 'clear/v1')
    user1 = json.loads(re.post_register('validemail@gmail.com', '123abc!@#', 'Hayden', 'Everest').text)
    return {'user1' : user1}

@pytest.fixture(scope='function')
def setup1():
    requests.delete(config.url + 'clear/v1')

    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password', 'name_first' : 'Test User', 'name_last' : '1'})
    login1_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password'})
    login1_token = login1_response.json()

    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password', 'name_first' : 'Test User', 'name_last' : '2'})
    login2_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser2@gmail.com', 'password' : 'testuser2password'})
    login2_token = login2_response.json()

    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password', 'name_first' : 'Test User', 'name_last' : '3'})
    login3_response = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser3@gmail.com', 'password' : 'testuser3password'})
    login3_token = login3_response.json()

    return [login1_token['token'], login2_token['token'], login3_token['token']]

############################################
# user_profile_setname_v1 tests
############################################
# Test to see if an input error is thrown if a users' firtname is less than 1 character
# or more than 50 characters
def test_user_invalid_firstname(setup):
    user1 = setup['user1']
    assert re.put_user_profile_setname(user1['token'], "", "Everest").status_code == INPUTERROR # Less than 1 character
    assert re.put_user_profile_setname(user1['token'],
                                    "111111111111111111111111111111111111111111111111111", "Everest").status_code == INPUTERROR # More than 50 characters

# Test to see if a users' name saves if it is exactly 1 or 50 characters
def test_name_boundaries(setup):
    user1 = setup['user1']
    assert re.put_user_profile_setname(user1['token'], "A", "Everest").status_code != INPUTERROR # Exactly 1 character
    assert re.put_user_profile_setname(user1['token'],
                                    "11111111111111111111111111111111111111111111111111", "Everest").status_code != INPUTERROR # Exactly 50 characters

# Test to see if an input error is thrown if a users' lastname is less than 1 character
# or more than 50 characters
def test_user_invalid_lastname(setup):
    user1 = setup['user1']
    assert (re.put_user_profile_setname(user1['token'], "I work", "").status_code == INPUTERROR) # Less than 1 character
    assert (re.put_user_profile_setname(user1['token'], "I work",
                                        "111111111111111111111111111111111111111111111111111").status_code == INPUTERROR) # More than 50 characters

# Test to see if an input error is thrown if a users' firtname and lastname is less than 1 character
# or more than 50 characters
def test_user_invalid_firstname_lastname(setup):
    user1 = setup['user1']
    assert (re.put_user_profile_setname(user1['token'], "", "").status_code == INPUTERROR) # Less than 1 character
    assert (re.put_user_profile_setname(user1['token'],
                                        "111111111111111111111111111111111111111111111111111",
                                        "111111111111111111111111111111111111111111111111111").status_code == INPUTERROR) # More than 50 characters

# Test to see if a users' first and last name are saved if the name boundary conditions are met
def test_user_valid_firstname_lastname(setup):
    user1 = setup['user1']
    re.put_user_profile_setname(user1['token'], "Jordan", "Terzian")
    new_name = json.loads(re.get_user_profile(user1['token'], user1['auth_user_id']).text)['user']
    assert (new_name['name_first'] == 'Jordan')
    assert (new_name['name_last'] == 'Terzian')



############################################
# user_profile_setemail_v1 tests
############################################
# Test to see if an input error is thrown if a users' email does not follow the specs valid format
def test_user_invalid_email(setup):
    user1 = setup['user1']
    assert (re.put_user_profile_setemail(user1['token'], "Jordan@swag").status_code == INPUTERROR) # First invalid email
    assert (re.put_user_profile_setemail(user1['token'], "Torch.com.au").status_code == INPUTERROR) # Second invalid email

# Test to see if an input error is thrown if a users' email is already being used by another user
def test_user_duplicate_email(setup):
    re.post_register('validemail@gmail.com', '123abc!@#', 'Hayden', 'Everest')
    user2 = json.loads(re.post_register('validemail2@gmail.com', '123abc!@#', 'Jordan', 'Terzian').text)
    assert (re.put_user_profile_setemail(user2['token'], "validemail@gmail.com").status_code == INPUTERROR)

# Test to see if a users email is saved if it is in the valid format and not a duplicate of another users'
# email
def test_user_valid_email(setup):
    user1 = setup['user1']
    re.put_user_profile_setemail(user1['token'], "newvalidemail@gmail.com")
    new = json.loads(re.get_user_profile(user1['token'], user1['auth_user_id']).text)['user']
    assert (new['email'] == "newvalidemail@gmail.com")


############################################
# user_profile_sethandle_v1 tests
############################################
# Test to see if an input error is thrown if a users' handle is less than 3 characters or more than 20
# characters
def test_user_invalid_handle(setup):
    user1 = setup['user1']
    assert (re.put_user_profile_sethandle(user1['token'], "x").status_code == INPUTERROR) # Less than 3 characters
    assert (re.put_user_profile_sethandle(user1['token'], "xxxxxxxxxxxxxxxxxxxxxx").status_code == INPUTERROR) # More than 20 characters

# Test to see if a users' handle saves if it is exactly 3 or 20 characters
def test_handle_boundaries(setup):
    user1 = setup['user1']
    assert re.put_user_profile_sethandle(user1['token'], "xxx").status_code != INPUTERROR # Exactly 3 characters
    assert re.put_user_profile_sethandle(user1['token'], "xxxxxxxxxxxxxxxxxxxx").status_code != INPUTERROR # Exactly 20 characters

# Test to see if an input error is thrown if a users' handle includes a non alphanumeric value
def test_user_handle_not_alphanumeric(setup):
    user1 = setup['user1']
    assert (re.put_user_profile_sethandle(user1['token'], "!@#$").status_code == INPUTERROR)

# Test to see if an input error is thrown if a users' handle is the same as another users'
def test_duplicate_handle(setup):
    user1 = setup['user1']
    re.put_user_profile_sethandle(user1['token'], "Swaggy")
    user2 = json.loads(re.post_register('validemail2@gmail.com', '123abc!@#', 'Jordan', 'Terzian').text)
    assert (re.put_user_profile_sethandle(user2['token'], "Swaggy").status_code == INPUTERROR)

# Test to see if a users' handle saves if it is not a duplicate of another users', is in alphanumeric form
# and if the boundary conditions are met
def test_valid_handle(setup):
    user1 = setup['user1']
    re.put_user_profile_sethandle(user1['token'], "Swaggy")
    new = json.loads(re.get_user_profile(user1['token'], user1['auth_user_id']).text)['user']
    assert (new['handle_str'] == "Swaggy")


############################################
# user_profile_v1 tests
############################################
# Test to see if an input error is thrown if the u_id does not refer to a valid user
def test_invalid_u_id(setup):
    user1 = setup['user1']
    assert (re.get_user_profile(user1['token'], -1).status_code == INPUTERROR)

# Test to see if the users profile is returned if the u_id belongs to a valid user
def test_user_profile_v1(setup):
    user1 = setup['user1']
    assert (json.loads(re.get_user_profile(user1['token'], user1['auth_user_id']).text)['user'] == {
                'u_id': 1,
                'email': 'validemail@gmail.com',
                'name_first': 'Hayden',
                'name_last': 'Everest',
                'handle_str': 'haydeneverest',
                'profile_img_url': None,
                'reset_code' : None
            })

############################################
# users_all_v1 tests
############################################
# Test to see if all users are returned if a token is passed in
def test_users_all(setup):
    register_response = requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password', 'name_first' : "Test User", 'name_last' : "1"})
    token = register_response.json()['token']

    users_all_response = requests.get(config.url + 'users/all/v1', params={'token' : token})
    users_all_result = users_all_response.json()

    assert users_all_result['users'][1] == {
                'u_id': 2,
                'email': 'testuser1@gmail.com',
                'name_first': 'Test User',
                'name_last': '1',
                'handle_str': 'testuser1',
                'profile_img_url': None
            }


############################################
# user_stats_v1 tests
############################################
# Test that user_stats returns properly
def test_user_stats_returns(setup1):
    requests.post(config.url + 'channels/create/v2', json={'token' : setup1[0], 'name' : 'Test Channel 12', 'is_public' : True})
    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup1[0], 'name' : 'Test Channel 1', 'is_public' : True})
    channel_id = channel_create.json()['channel_id']

    users = setup1[1: ]
    for token in users:
        requests.post(config.url + 'channel/join/v2', json={'token' : token, 'channel_id' : channel_id})
        requests.post(config.url + 'message/send/v1', json={'token' : token, 'channel_id' : channel_id, 'message' : MESSAGE})

    dummy_dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup1[0], 'u_ids' : [2,3]})
    dummy_dm_id = dummy_dm_create.json()['dm_id']
    re.post_message_senddm(token, dummy_dm_id, MESSAGE)

    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser12@gmail.com', 'password' : 'testuser1password', 'name_first' : 'Test User', 'name_last' : '1'})
    usernone = requests.post(config.url + 'auth/login/v2', json={'email' : 'testuser1@gmail.com', 'password' : 'testuser1password'})
    usernone_token = usernone.json()['token']
    requests.get(config.url + 'user/stats/v1', params={'token' : usernone_token})

    user_stats_response = requests.get(config.url + 'user/stats/v1', params={'token' : token})
    user_stats_result = user_stats_response.json()

    timestamp = int(datetime.now(timezone.utc).timestamp())
    assert user_stats_result == {
        'channels_joined': [{'num_channels_joined': 1, 'timestamp': timestamp}],
        'dms_joined': [{'num_dms_joined': 1, 'timestamp': timestamp}],
        'messages_sent': [{'num_messages_sent': 2, 'timestamp': timestamp}],
        'involvement_rate': [{'involvement_rate': 0.6666666666666666, 'timestamp': timestamp}]
        }

############################################
# users_stats_v1 tests
############################################
# Test that users_stats returns properly
def test_return_workspace_stats(setup1):
    requests.post(config.url + 'auth/register/v2', json={'email' : 'testuser132a@gmail.com', 'password' : 'testuser1passworwd', 'name_first' : 'Test fUser', 'name_last' : '1s'})

    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup1[0], 'name' : 'Test Channel 1', 'is_public' : True})
    channel_id = channel_create.json()['channel_id']

    users = setup1[1: ]
    for token in users:
        requests.post(config.url + 'channel/join/v2', json={'token' : token, 'channel_id' : channel_id})
        requests.post(config.url + 'message/send/v1', json={'token' : token, 'channel_id' : channel_id, 'message' : MESSAGE})

    dummy_dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup1[0], 'u_ids' : [2,3]})
    dummy_dm_id = dummy_dm_create.json()['dm_id']

    users_stats_response = requests.get(config.url + 'users/stats/v1', params={'token' : token})
    users_stats_result = users_stats_response.json()

    timestamp = int(datetime.now(timezone.utc).timestamp())
    assert users_stats_result == {
        'channels_exist': [{'num_channels_exist': 1, 'timestamp': timestamp}],
        'dms_exist': [{'num_dms_exist': 1, 'timestamp': timestamp}],
        'messages_exist': [{'num_messages_exist': 2, 'timestamp': timestamp}],
        'utilization_rate': [{'utilization_rate': 0.75, 'timestamp': timestamp}]
        }

# Test the utilization rate involving dm
def test_dm_utilization_rate(setup1):

    dummy_dm_create = requests.post(config.url + 'dm/create/v1', json={'token' : setup1[0], 'u_ids' : [2,3]})
    dummy_dm_id = dummy_dm_create.json()['dm_id']

    users_stats_response = requests.get(config.url + 'users/stats/v1', params={'token' : setup1[0]})
    users_stats_result = users_stats_response.json()

    timestamp = int(datetime.now(timezone.utc).timestamp())
    assert users_stats_result == {
        'channels_exist': [{'num_channels_exist': 0, 'timestamp': timestamp}],
        'dms_exist': [{'num_dms_exist': 1, 'timestamp': timestamp}],
        'messages_exist': [{'num_messages_exist': 0, 'timestamp': timestamp}],
        'utilization_rate': [{'utilization_rate': 1.0, 'timestamp': timestamp}]
        }

# Test the utilization rate involving channel
def test_channel_utilization_rate(setup1):

    channel_create = requests.post(config.url + 'channels/create/v2', json={'token' : setup1[0], 'name' : 'Test Channel 1', 'is_public' : True})
    channel_id = channel_create.json()['channel_id']

    users = setup1[1: ]
    for token in users:
        requests.post(config.url + 'channel/join/v2', json={'token' : token, 'channel_id' : channel_id})
        requests.post(config.url + 'message/send/v1', json={'token' : token, 'channel_id' : channel_id, 'message' : MESSAGE})

    users_stats_response = requests.get(config.url + 'users/stats/v1', params={'token' : token})
    users_stats_result = users_stats_response.json()

    timestamp = int(datetime.now(timezone.utc).timestamp())
    assert users_stats_result == {
        'channels_exist': [{'num_channels_exist': 1, 'timestamp': timestamp}],
        'dms_exist': [{'num_dms_exist': 0, 'timestamp': timestamp}],
        'messages_exist': [{'num_messages_exist': 2, 'timestamp': timestamp}],
        'utilization_rate': [{'utilization_rate': 1.0, 'timestamp': timestamp}]
        }

############################################
#user_profile_uploadphoto_v1 tests
############################################

# Expect to match since all the info are correct
def test_user_profile_uploadphoto_right_size_after_crop(setup):
    user = setup['user1']
    img_url = 'http://pic3.zhimg.com/50/v2-d17cdaea9ef029429bcf29929b42d8a0_hd.jpg'

    assert re.post_user_profile_uploadphoto(user['token'], img_url, 0, 0, 100, 100).status_code not in (ACCESSERROR, INPUTERROR)
    resp = re.get_user_profile(user['token'], user['auth_user_id']).json()
    file = resp['user']['profile_img_url'].split('/')[-1]
    img = requests.get(config.url + 'static/' + file)
    image = Image.open(BytesIO(img.content))
    assert image.size == (100, 100)

# Expect to match since all the info are correct
def test_user_profile_uploadphoto_multiple_times(setup):
    user = setup['user1']
    img_url = 'http://pic3.zhimg.com/50/v2-d17cdaea9ef029429bcf29929b42d8a0_hd.jpg'

    assert re.post_user_profile_uploadphoto(user['token'], img_url, 0, 0, 700, 700).status_code not in (ACCESSERROR, INPUTERROR)
    assert re.post_user_profile_uploadphoto(user['token'], img_url, 0, 0, 600, 600).status_code not in (ACCESSERROR, INPUTERROR)
    assert re.post_user_profile_uploadphoto(user['token'], img_url, 0, 0, 500, 500).status_code not in (ACCESSERROR, INPUTERROR)
    resp = re.get_user_profile(user['token'], user['auth_user_id']).json()
    file = resp['user']['profile_img_url'].split('/')[-1]
    img = requests.get(config.url + 'static/' + file)
    image = Image.open(BytesIO(img.content))
    assert image.size == (500, 500)

# Expect to raise InputError since img_url returns an HTTP status other than 200
def test_user_profile_uploadphoto_invalid_img_url(setup):
    user = setup['user1']
    img_url = 'joke'
    assert re.post_user_profile_uploadphoto(user['token'], img_url, 0, 0, 100, 100).status_code == INPUTERROR
    img_url = 'http://www.google.com'
    assert re.post_user_profile_uploadphoto(user['token'], img_url, 0, 0, 100, 100).status_code == INPUTERROR

# Expect to raise InputError since any of x_start, y_start,
# x_end, y_end are not within the dimensions of the image at the URL
def test_user_profile_uploadphoto_invalid_size_choice(setup):
    user = setup['user1']
    img_url = 'http://pic3.zhimg.com/50/v2-d17cdaea9ef029429bcf29929b42d8a0_hd.jpg'
    assert re.post_user_profile_uploadphoto(user['token'], img_url, 0, 0, 0, 0).status_code == INPUTERROR
    assert re.post_user_profile_uploadphoto(user['token'], img_url, -1, 0, 0, 0).status_code == INPUTERROR
    assert re.post_user_profile_uploadphoto(user['token'], img_url, 0, -1, 0, 0).status_code == INPUTERROR
    assert re.post_user_profile_uploadphoto(user['token'], img_url, 0, 0, -1, 0).status_code == INPUTERROR
    assert re.post_user_profile_uploadphoto(user['token'], img_url, 0, 0, 0, -1).status_code == INPUTERROR

# Expect to raise InputError since x_end is
# less than x_start or y_end is less than y_start
def test_user_profile_uploadphoto_conflicting_size_choice(setup):
    user = setup['user1']
    img_url = 'http://pic3.zhimg.com/50/v2-d17cdaea9ef029429bcf29929b42d8a0_hd.jpg'
    assert re.post_user_profile_uploadphoto(user['token'], img_url, 100, 0, 50, 0).status_code == INPUTERROR
    assert re.post_user_profile_uploadphoto(user['token'], img_url, 0, 100, 0, 50).status_code == INPUTERROR

# Expect to raise InputError since image uploaded is not a JPG
def test_user_profile_uploadphoto_not_jpg(setup):
    user = setup['user1']
    img_url = 'http://image.16pic.com/00/90/60/16pic_9060222_s.jpg?imageView2/0/format/png'
    assert re.post_user_profile_uploadphoto(user['token'], img_url, 0, 0, 100, 100).status_code == INPUTERROR
