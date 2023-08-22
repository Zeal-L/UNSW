from src.data_store import data_store
from src.error import InputError
from src.error import AccessError
from src.helper import check_email, duplicate_email_check, duplicate_handle_check, get_user, check_token, \
    check_valid_auth_user_id, decode_jwt

import uuid
from flask import url_for
from urllib import request as urlrequest
from PIL import Image
import io
from datetime import datetime, timezone


'''
<Returns a list of all users and their associated details.>

Arguments:
    <token> (<String>)    - <Holds the users information>

Exceptions:
    N/A

Return Value:
    Returns <users> if user in channel is in data_store

'''
def users_all_v1(token):

    # Check that token is valid
    check_token(token)

    users = []
    for user in data_store.get()['users']:
        if (user['name_first'] == 'Removed' and
            user['name_last'] == 'user' and
            user['email'] == '' and
            user['handle_str'] == ''):
            continue

        users.append({'u_id': user['u_id'],
                    'email': user['email'],
                    'name_first': user['name_first'],
                    'name_last': user['name_last'],
                    'handle_str':user['handle_str'],
                    'profile_img_url':user['profile_img_url']})
    return {'users': users}

'''
<For a valid user, returns information about their user_id, email, first name, last name, and handle>

Arguments:
    <token> (<String>)    - <Holds the users information>
    <u_id> (<Integer>)    - <The users identification number>

Exceptions:
    InputError  - Occurs when u_id does not refer to a valid user
    AccessError - Occurs when token is invalid

Return Value:
    Returns the users profile dictionary

'''
def user_profile_v1(token, u_id):

    ###INPUT ERRORS###
    # Check valid u_id

    check_valid_auth_user_id(u_id)

    ###ACCESS ERRORS###
    # Check that token is valid
    check_token(token)



    user = get_user(u_id)
    user_profile_dictionary = {
        'u_id': u_id,
        'email': user['email'],
        'name_first': user['name_first'],
        'name_last': user['name_last'],
        'handle_str': user['handle_str'],
        'profile_img_url' : user['profile_img_url'],
        'reset_code' : user['reset_code']
        }

    return user_profile_dictionary

'''
<Update the authorised user's first and last name>

Arguments:
    <token> (<String>)    - <Holds the users information>
    <name_first> (<String>)    - <Stores the users first name>
    <name_last> (<String>)    - <Stores the users last name>

Exceptions:
    InputError  - Occurs when length of name_first is not between 1 and 50 characters inclusive
    InputError - Occurs when length of name_last is not between 1 and 50 characters inclusive

Return Value:
    Function returns an empty dictionary

'''
def user_profile_setname_v1(token, name_first, name_last):
    ###INPUT ERRORS###
    if len(name_first) > 50 or len(name_first) < 1:
        raise InputError(description = "Length of name_first is not between 1 and 50 characters inclusive")

    if len(name_last) > 50 or len(name_last) < 1:
        raise InputError(description = "Length of name_last is not between 1 and 50 characters inclusive")


    ###ACCESS ERRORS###
    # Check that token is valid
    check_token(token)

    u_id = decode_jwt(token)['u_id']

    user = get_user(u_id)

    user['name_first'] = name_first
    user['name_last'] = name_last

    return {}

'''
<Update the authorised user's email address>

Arguments:
    <token> (<String>)    - <Holds the users information>
    <email> (<String>)    - <Stores the users email address>

Exceptions:
    InputError  - Occurs when email entered is not a valid email
    InputError - Occurs when email address is already being used by another user

Return Value:
    Function returns an empty dictionary

'''
def user_profile_setemail_v1(token, email):

    ###INPUT ERRORS###
    if check_email(email) == False:
        raise InputError(description = "Email entered is not a valid email")

    if duplicate_email_check(email) == True:
        raise InputError(description = "Email address is already being used by another user")

    ###ACCESS ERRORS###
    # Check that token is valid
    check_token(token)

    u_id = decode_jwt(token)['u_id']

    user = get_user(u_id)

    user['email'] = email

    return {}

'''
<Update the authorised user's handle (i.e. display name)>

Arguments:
    <token> (<String>) - <Holds the users information>
    <handle_str> (<String>) - <Stores the users display name>
    ...

Exceptions:
    InputError  - Occurs when length of handle_str is not between 3 and 20 characters inclusive
    InputError - Occurs when handle_str contains characters that are not alphanumeric
    InputError - Occurs when the handle is already used by another user

Return Value:
    Function returns an empty dictionary

'''
def user_profile_sethandle_v1(token, handle_str):

    ###INPUT ERRORS###
    if len(handle_str) > 20 or len(handle_str) < 3:
        raise InputError(description = "Length of handle_str is not between 3 and 20 characters inclusive")

    if handle_str.isalnum() == False:
        raise InputError(description = "handle_str contains characters that are not alphanumeric")

    if duplicate_handle_check(handle_str) == True:
        raise InputError(description = "The handle is already used by another user")

    ###ACCESS ERRORS###
    # Check that token is valid
    check_token(token)

    u_id = decode_jwt(token)['u_id']

    user = get_user(u_id)

    user['handle_str'] = handle_str

    return {}

'''
<Given a URL of an image on the internet, crops the image within bounds (x_start, y_start) and (x_end, y_end).
Position (0,0) is the top left.>

Arguments:
    <token> (<String>) - <Holds the users information>
    <img_url> (<String>) - <Stores the url of the image>
    <x_start> (<Integer>) - <Stores the horizontal start coordinate of the image>
    <x_end> (<Integer>) - <Stores the horizontal end coordinate of the image>
    <y_start> (<Integer>) - <Stores the vertical start coordinate of the image>
    <y_end> (<Integer>) - <Stores the vertical end coordinate of the image>
    ...

Exceptions:
    InputError  - img_url returns an HTTP status other than 200
    InputError - any of x_start, y_start, x_end, y_end are not within the dimensions of the image at the URL
    InputError - x_end is less than x_start or y_end is less than y_start
    InputError - image uploaded is not a JPG

Return Value:
    Function returns an empty dictionary

'''
def user_profile_uploadphoto_v1(token, img_url, x_start, y_start, x_end, y_end):

    check_token(token)

    u_id = decode_jwt(token)['u_id']
    user = get_user(u_id)

    ###INPUT ERRORS###
    try:
        # Open the image file
        descriptor = urlrequest.urlopen(img_url)
        file = io.BytesIO(descriptor.read())
        image = Image.open(file)
    except:
        raise InputError(description = "img_url returns an HTTP status other than 200") from InputError

    if image.format != "JPEG":
        raise InputError(description = "Image uploaded is not a JPG")

    if x_end < x_start or y_end < y_start:
        raise InputError(description = "x_end is less than x_start or y_end is less than y_start")


    width, height = image.size

    ###INPUT ERRORS INVOLVING WIDTH AND HEIGHT ISSUES###
    if x_end >= width or x_end < 0 or x_start >= width or x_start <  0:
        raise InputError(description = "Not within the dimensions of the image at the URL")

    if y_end >= height or y_end < 0 or y_start >= height or y_start <  0:
        raise InputError(description = "Not within the dimensions of the image at the URL")

    if y_start == y_end or x_start == x_end:
        raise InputError(description = "Not within the dimensions of the image at the URL")

    # Crop the image
    cropped_image = image.crop((x_start, y_start, x_end, y_end))

    # save URL in data base
    file_name = uuid.uuid4().hex
    path = file_name + '.jpg'
    cropped_image.save('photos/' + path, 'JPEG')

    url = url_for('static', filename = path, _external = True)
    user['profile_img_url'] = url

    return {}

'''
<Fetches the required statistics about this user's use of UNSW Streams.>

Arguments:
     <token> (<String>) - <Holds the users information>
     ...

Exceptions:
     None

Return Value:
     Function returns user_stats dictionary

'''
def user_stats_v1(token):
    check_token(token)
    u_id = decode_jwt(token)['u_id']
    user = get_user(u_id)

    # User stat counters
    num_channels_joined = 0
    num_msgs_sent = 0
    num_dms_joined = 0

    # Overall stat counters
    num_channels = 0
    num_dms = 0
    num_msgs = 0

    # Number of channels user has joined
    for channel in data_store.get()['channels']:
        members = channel['all_members'] + channel['owner_members']
        if user in members:
            num_channels_joined += 1

    # Number of messages user has sent in channels and dms

    for channel in data_store.get()['channels']:
       for message in channel['messages']:
            if user['u_id'] == message['u_id']:
                num_msgs_sent += 1

    for dm in data_store.get()['dms']:
        for message in dm['messages']:
            if user['u_id'] == message['u_id']:
                num_msgs_sent += 1

    # Number of dms user has joined
    for dm in data_store.get()['dms']:
        dm_members = dm['all_members'] + dm['owner_members']
        if user in dm_members:
            num_dms_joined += 1

    # Total number of channels
    for dummy_channel in data_store.get()['channels']:
        num_channels += 1

    # Total number of messages
    for dummy_message in data_store.get()['messages']:
        num_msgs += 1

    # Total number of dms
    for dummy_dm in data_store.get()['dms']:
        num_dms += 1

    involvement_rate =(num_channels_joined + num_dms_joined + num_msgs_sent)/(num_channels + num_msgs + num_dms)

    timestamp = int(datetime.now(timezone.utc).timestamp())

    user_stats = {
        'channels_joined': [{'num_channels_joined': num_channels_joined, 'timestamp': timestamp}],
        'dms_joined': [{'num_dms_joined': num_dms_joined, 'timestamp': timestamp}],
        'messages_sent': [{'num_messages_sent': num_msgs_sent, 'timestamp': timestamp}],
        'involvement_rate': [{'involvement_rate': involvement_rate, 'timestamp': timestamp}]
        }

    return user_stats

'''
<Fetches the required statistics about the use of UNSW Streams.>

Arguments:
    <token> (<String>) - <Holds the users information>
    ...

Exceptions:
    None

Return Value:
    Function returns workspace_stats dictionary

'''
def users_stats_v1(token):

    # User counters
    num_users = 0
    num_users_in_channels = 0
    num_users_in_dms = 0

    # Overall stat counters
    num_channels = 0
    num_dms = 0
    num_msgs = 0

    # Total number of channels
    for dummy_channel in data_store.get()['channels']:
        num_channels += 1

    # Total number of messages
    for dummy_message in data_store.get()['messages']:
        num_msgs += 1

    # Total number of dms
    for dummy_dm in data_store.get()['dms']:
        num_dms += 1

    # Total number of users
    for dummy_user in data_store.get()['users']:
        num_users += 1

    # Number of users who have joined a channel
    for user in data_store.get()['users']:
        for channel in data_store.get()['channels']:
            if user in channel['all_members'] or user in channel['owner_members']:
                num_users_in_channels += 1

    # Number of users who have joined a dm
    for user in data_store.get()['users']:
        for dm in data_store.get()['dms']:
            if user in dm['all_members'] or user in dm['owner_members']:
                num_users_in_dms += 1




    # Pick which utilization_rate based on spec conditions
    if num_users_in_channels < 1 and num_users_in_dms >= 1:
        utilization_rate = num_users_in_dms / num_users

    elif num_users_in_dms < 1 and num_users_in_channels >= 1:
        utilization_rate = num_users_in_channels / num_users

    elif num_users_in_dms >= 1 and num_users_in_channels >= 1:
        utilization_rate = num_users_in_channels / num_users

    timestamp = int(datetime.now(timezone.utc).timestamp())
    workspace_stats = {
        'channels_exist': [{'num_channels_exist': num_channels, 'timestamp': timestamp}],
        'dms_exist': [{'num_dms_exist': num_dms, 'timestamp': timestamp}],
        'messages_exist': [{'num_messages_exist': num_msgs, 'timestamp': timestamp}],
        'utilization_rate': [{'utilization_rate': utilization_rate, 'timestamp': timestamp}]
        }

    return workspace_stats
