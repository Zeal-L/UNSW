###############################################################################
# Helper Functions for COMP1531, Iteration 3. Written by Beagle, W13A
###############################################################################

#############################################
# Import(s)
#############################################
from src.data_store import data_store
from src.error import InputError, AccessError
import re
import hashlib
import jwt
import random
from tests.admin_test import GLOBAL_OWNERS, MEMBERS

#############################################
# Global Variable(s)
#############################################

session_tracker = 0
SECRET = 'Curse you Perry the Platypus.'
REACTS = [1]

def reset_session_tracker():
    global session_tracker
    session_tracker = 0


'''
<When this function is given a valid channel ID, it checks if the channel is public.>

Arguments:
    <channel_id> (<Integer>) - <The specific channels identification number>

Exceptions:
    InputError  - Occurs when channel_id does not refer to a valid channel.

Return Value:
    Returns true or false depending on whether the channel is public.
'''
# Function to check if channel is public or not
def check_channel_publicity(channel_id):
    # Get the data store
    store = data_store.get()

    # Check if channel_id is valid
    check_valid_channel_id(channel_id)

    output = False

    for check in store["channels"]:
        if check["channel_id"] == channel_id:
            if check["is_public"] == True:
                # If channel is public set output equal to true
                output = True

    return output

'''
<When this function is given a valid channel ID and is accompanied by an authorised valid user ID, it returns whether the user is an owner member.>

Arguments:
    <auth_user_id> (<Integer>) - <The user identification number of a pre-existing channel member.>
    <channel_id> (<Integer>) - <The specific channels identification number>

Exceptions:
    InputError  - Occurs when channel_id does not refer to a valid channel.
    AccessError - When auth_user_id does not refer to a valid user.

Return Value:
    Returns true or false depending on whether the user is an owner of the channel.
'''
# Function to check if authorised user is a global owner
def check_if_owner(auth_user_id, channel_id):
    # Check that channel_id is valid
    check_valid_channel_id(channel_id)
    # Check that auth_user_id is valid
    check_valid_auth_user_id(auth_user_id)

    # Get the data store
    store = data_store.get()

    output = False

    for check in store["channels"]:
        if check['channel_id'] == channel_id:
            for user in check['owner_members']:
                if user["u_id"] == auth_user_id:
                    # If user is an owner member set output equal to true
                    output = True
    for user in store["users"]:
        if user["u_id"] == auth_user_id and user["permission_id"] == GLOBAL_OWNERS:
            output = True

    return output

'''
<When this function is given a channel ID, the validity is returned.>

Arguments:
    <channel_id> (<Integer>) - <The specific channels identification number>

Exceptions:
    InputError  - Occurs when channel_id does not refer to a valid channel.

Return Value:
    Returns nothing.
'''
# Function to check if authorised user is a valid auth_user_id
def check_valid_channel_id(channel_id):
    # Get the data store
    store = data_store.get()

    # Check that channel_id is in channel["channel_id"]
    for channel in store["channels"]:
        if channel["channel_id"] == channel_id:
            return
    raise InputError("channel_id does not refer to a valid channel")

# Following functions need comments according to docstring Zeal, also need tests
# in helper_test.py

def generate_new_session_id():
    global session_tracker
    session_tracker += 1
    return session_tracker

#add this to helper file.
def encrypt(input_string):
    return hashlib.sha256(input_string.encode()).hexdigest()

#add this to helper file.
def generate_jwt(u_id, session_id):
    return jwt.encode({'u_id': u_id, 'session_ids': session_id}, SECRET, algorithm = "HS256")

#add this to helper file.
def decode_jwt(encode_jwt):
    return jwt.decode(encode_jwt, SECRET, algorithms = ['HS256'])

#add this to helper file.
def validation(email, password):

    #Validate email
    regex = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'

    if(re.fullmatch(regex, email) == None):
        raise InputError('Email is Invalid')

    if len(password) < 6:
        raise InputError("Password is invalid")


'''
<When this function is given a token, the validity is checked. An accesserror is raised if the token is invalid>

Arguments:
    <token> (<String>) - <The token of a streams user.>

Exceptions:
    AccessError - When token is not valid.

Return Value:
    Returns nothing.
'''
def check_token(token):
    data = data_store.get()
    payload = jwt.decode(token, SECRET, algorithms = ['HS256'])
    u_id = payload['u_id']
    session_id = payload['session_ids']

    for users in data['users']:
        if u_id == users['u_id']:
            if session_id in users['session_ids']:
                return

    raise AccessError(description = 'invalid token')


'''
<Check that a users email matches designated expression>

Arguments:
    <email> (<String>)    - <Stores the users email>

Exceptions:
    No Exceptions

Return Value:
    Returns <True> on <condition that email is in correct expression>
    Returns <False> on <condition that email is not in correct expression>

'''
def check_email(email):
    # Regular expression
    regex = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'
    # If email matches this expression return true
    if (re.fullmatch(regex, email) != None):
        return True
    else:
        return False


'''
<Check that email is not already in use>

Arguments:
    <email> (<String>)    - <Stores the users email>

Exceptions:
    No Exceptions

Return Value:
    Returns <True> on <condition that the email is already in use>
    Returns <False> on <condition that the email is not in use>

'''
def duplicate_email_check(email):
    store = data_store.get()
    for user in store['users']:
        if user['email'] == email:
            return True
    return False


'''
<Check that handle is not already in use>

Arguments:
    <handle_str> (<String>) - <Stores the users display name>


Exceptions:
    No Exceptions

Return Value:
    Returns <True> on <condition that the handle is already in use>
    Returns <False> on <condition that the handle is not in use>

'''
def duplicate_handle_check(handle_str):
    store = data_store.get()
    for user in store['users']:
        if user['handle_str'] == handle_str:
            return True
    return False

'''
<Check if user is a member of channel>

Arguments:
    <channel_id> (<Integer>) - <The specific channels' identification number>
    <u_id> (<Integer>) - <The users' identification number>

Exceptions:
    No Exceptions
Return Value:
    Returns <Output (True)> on <condition that user is already in the channel>
    Returns <Output (False)> on <condition that user is not already in the channel>

'''
def check_if_member(channel_id, u_id):
    # Get the data store
    store = data_store.get()
    Output = False
    for channel in store["channels"]:
        if channel['channel_id'] == channel_id:
            for user in channel['owner_members']:
                if user["u_id"] == u_id:
                    Output = True
            for user in channel['all_members']:
                if user["u_id"] == u_id:
                    # If user is already member of channel set Output equal to true
                    Output = True
    return Output

# Given a user id return user dict
def get_user(u_id):
    target = {}
    for user in data_store.get()['users']:
        if u_id == user['u_id']:
            target = user
    return target

'''
<When this function is given an auth user ID, the validity is returned.>

Arguments:
    <u_id> (<integer>) - <The user identification number of a pre-existing channel member.>

Exceptions:
    InputError - When u_id is not valid.

Return Value:
    Returns nothing.
'''
def check_valid_auth_user_id(u_id):
    store = data_store.get()
    for user in store['users']:
        if user['u_id'] == u_id:
            return
    raise InputError("u_id does not refer to a valid user")

'''
<When this function is given a message, the function checks that the message is valid.>

Arguments:
    <message> (<String>) - <The message for which the length needs to be checked.>

Exceptions:
    InputError - When message is greater then 1000 characters
    InputError - When message is less then 1 character

Return Value:
    Returns nothing.
'''
def check_message_length(message):
    # Check length of message
    if len(message) > 1000:
        raise InputError(description = "Message length is greater then 1000")
    elif len(message) < 1:
        raise InputError(description = "Message length is less then 1")

'''
<When this function is given a message id, the function checks that the message is valid.>

Arguments:
    <message> (<String>) - <The message for which the length needs to be checked.>

Exceptions:
    InputError - When message_id is valid but does not refer to a message that the user is authorized to work on
    InputError - When message_id is invalid

Return Value:
    Returns nothing.
'''
def check_valid_message_id(message_id, u_id):
    store = data_store.get()
    # User is unauthorised by default
    unauthorised_user = True
    # Message does not exist by default
    message_does_not_exist = True
    for message in store['messages']:
        if message_id in message.keys():
            message_does_not_exist = False
    if message_does_not_exist:
        raise InputError(description = "Invalid message ID")
    
    channel_id = store['messages'][message_id]
    channel_id = channel_id[message_id][0]
    for channel in store["channels"]:
        if channel_id == channel["channel_id"]:
            for user in channel["owner_members"]:
                if user["u_id"] == u_id:
                    unauthorised_user = False
                    break
            for user in channel["all_members"]:
                if user["u_id"] == u_id:
                    unauthorised_user = False
                    break
    for channel in store['dms']:
        if channel_id == channel["dm_id"]:
            for user in channel["owner_members"]:
                if user["u_id"] == u_id:
                    unauthorised_user = False
                    break
            for user in channel["all_members"]:
                if user["u_id"] == u_id:
                    unauthorised_user = False
                    break
    # If user is unauthorised then show an InputError
    if unauthorised_user:
        raise(InputError(description = "message_id does not refer to a valid message within a channel/DM that the authorised user has joined"))

'''
Given a valid token, find the user in data store which is tied to it

Arguments:
    token (string) - a string of a already verified JWT which when decoded reveals a user's id number and the session id.

Exceptions:

Return Value:
    Returns the user id tied to the valid JWT token
'''
# Get the user associated with a valid token
def user_from_token(token):
    payload = jwt.decode(token, SECRET, algorithms=['HS256'])
    return payload['u_id']


def check_valid_u_id(u_id):
    '''
    <When this function is given an auth user ID, the validity is returned.>

    Arguments:
        <u_id> (<integer>) - <The user identification number.>

    Exceptions:
        InputError - Then the u_id passed in is not valid"

    Return Value:
        Returns nothing.
    '''
    store = data_store.get()
    for user in store["users"]:
        if user["u_id"] == u_id:
            return
    raise InputError("The u_id passed in is not valid")

def check_global_owner(u_id):
    '''
    <if the authorised user is not a global owner raise an AccessError.>

    Arguments:
        <u_id> (<integer>) - <The user identification number.>

    Exceptions:
        AccessError - when the authorised user is not a global owner

    Return Value:
        Returns nothing.
    '''
    store = data_store.get()
    for user in store["users"]:
        if user["u_id"] == u_id and user["permission_id"] == GLOBAL_OWNERS:
            return
    raise AccessError("the authorised user is not a global owner")

def check_only_global_owner(u_id):
    '''
    <if u_id refers to a user who is the only global owner raise an InputError.>

    Arguments:
        <u_id> (<integer>) - <The user identification number.>
    Exceptions:
        InputError - u_id refers to a user who is the only global owner

    Return Value:
        Returns nothing.
    '''
    store = data_store.get()
    counter = 0
    for user in store["users"]:
        if user["permission_id"] == GLOBAL_OWNERS:
            counter += 1
    for user in store["users"]:
        if user["u_id"] == u_id                         \
            and user["permission_id"] == GLOBAL_OWNERS  \
            and counter > 1:
            return
        elif user["u_id"] == u_id and user["permission_id"] == MEMBERS:
            return
    raise InputError("u_id refers to a user who is the only global owner")

def check_react_id(react_id):
    '''
    <Check if a given react id is valid.>

    Arguments:
        <react_id> (<integer>) - <The react identification number.>
    Exceptions:
        InputError - react_id refers to an invalid react.

    Return Value:
        Returns nothing.
    '''
    if react_id in REACTS:
        return
    else:
        raise InputError(description= "react_id is not a valid react ID - currently")


'''
Description:
    Given a user and message id, check that the message tied to the id exists in a channel or dm that the 
    user is a member of. This is a helper function primarily used in message/share/v1 

Arguments:
    user (dictionary) - dictionary as seen in the list of users in the data store
    message_id (integer) - id referring to a potentially valid message
Exceptions:
    InputError - The given id does not refer to a valid message sent by the user
'''

def find_message(user, message_id):
    data = data_store.get()
    channels = data['channels']
    dms = data['dms']

    valid_message_id = False
    for channel in channels:
        members = channel['owner_members'] + channel['all_members']
        if user in members:
            for message in channel['messages']:
                if message['message_id'] == message_id:
                    valid_message_id = True
                    return message
    for dm in dms:
        members = dm['owner_members'] + dm['all_members']
        if user in members:
            for message in dm['messages']:
                if message['message_id'] == message_id:
                    valid_message_id = True
                    return message
    if not valid_message_id:
        raise InputError(description='message id does not refer to a message in a channel/dm that the user is a part of')

