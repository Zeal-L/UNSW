#Imports
import json
import jwt

from src.helper import check_token, SECRET
from src.error import InputError, AccessError
from src.data_store import data_store
from src import config


# Helper Functions
'''
Given a valid token, find the user in data store which is tied to it

Arguments:
    token (string) - a string of a already verified JWT which when decoded reveals a user's id number and the session id.

Exceptions:

Return Value:
    Returns the user id tied to the valid JWT token
'''
def user_from_token(token):
    # Decode a valid token, return the user id
    payload = jwt.decode(token, SECRET, algorithms=['HS256'])
    return payload['u_id']


# Implementation for dm/create/v1:
'''
Create a dm directed to the users in u_ids. The owner of the dm is the user in the token.
The name of the DM is automatically generated based on the handles of the owner and member.

Arguments:
    token (string) - a string of a JWT which when decoded reveals a user's id number and the session id which
                     is then verified to determine if the user invoking the current function is authorized to do so.
    u_ids (list of integers) - a list of user id's which refer to potentially-valid users that have registered
Exceptions:
    InputError  - Occurs when there is an invalud u_id in the u_ids list
    AccessError - Occurs when the token passed into the function is invalid

Return Value:
    Returns a dictionary containing the dm's name and id {"dm_id" : 1, "name" : "user1handle, user2handle, user3handle"} upon
    the successful creation of the dm

'''
def dm_create_v1(token, u_ids):
    # Authenticate the token
    check_token(token)
    data = data_store.get()

    # Check the validity of each user_id
    for u_id in u_ids:
        found = False
        for user in data['users']:
            if user['u_id'] == u_id:
                found = True
        if not found:
            raise InputError(description=f'{u_id} is an invalid user id')

    creator = user_from_token(token)
    add_user = data['users'][creator-1]

    members = []
    for id in u_ids:
        members.append(data['users'][id-1])

    handles = []
    for user in u_ids:
        handles.append(data['users'][user-1]['handle_str'])
    handles.append(data['users'][creator-1]['handle_str'])
    name = ', '.join(sorted(handles))

    id = len(data['dms'])

    # Create a new dm with the appropriate information and append it to the data store
    data['dms'].append({
        'name' : name,
        'dm_id' : id,
        'creator_id' : creator, #
        'owner_members' : [add_user], # decrypt token to get the user
        'all_members' : members,
        'messages' : []
    })

    # Send a notification to those who were just added to the dm "{user handle} added you to {dm_name}"
    handle = data['users'][creator-1]['handle_str']
    notification_message = str(handle) + ' added you to ' + str(name)
    for u in u_ids:
        data['users'][u-1]['notifications'].append({
            'channel_id' : -1,
            'dm_id' : id,
            'notification_message' : notification_message
        })
    return {'dm_id' : id}

# Implementation for dm/details/v1
'''
Given a valid dm_id and the token of a user who is a member of the DM, return basic details of the DM including name and list of members
Arguments:
    token (string) - a string of a potentially valid JWT which when decoded reveals a user's id number and the session id.
    dm_id (integer) - an id value which potentially refers to a valid dm in the data store
Exceptions:
    InputError - when the given dm_id does not refer to a valid dm in the data store
    AccessError - when the given token does not refer to a valid user and sesion_id
    AccessError - when the given dm_id and token are valid but the user tied to the token is not a member of the dm tied to the id
Return Value:
    Returns a dictionary contaiing the name of dm and a list of user dictionaries when given a valid dm id and the token of a user who is a member of said dm

'''
def dm_details_v1(token, dm_id):
    # Check the validity of the token
    check_token(token)
    data = data_store.get()
    # Then check the dm_id
    if dm_id < 0 or dm_id > len(data['dms']) or len(data['dms']) == 0:
        raise InputError(description='f{dm_id} is an invalid dm id')

    target_dm = data['dms'][dm_id]
    target_user = data['users'][user_from_token(token)-1]
    all_members = target_dm['owner_members'] + target_dm['all_members']
    if target_user not in all_members:
        raise AccessError(description="Passed a valid dm but user is not a member of the dm")
    # Check the members of target dm
    members = []
    for user in all_members:
        members.append({
            'u_id' : user['u_id'],
            'email' : user['email'],
            'name_first' : user['name_first'],
            'name_last' : user['name_last'],
            'handle_str' : user['handle_str'],
            'profile_img_url' : user['profile_img_url']
        })
    return {'name' : target_dm['name'], 'members' : members}

# Implementation for dm/list/v1
'''
Return a list of DMs that the given user is a member of

Arguments:
    token (string) - a string of a potentially authenticated JWT which when decoded reveals a user's id number and the session id.
    dm_id (integer) - integer which contains an potentially valid id for a dm

Exceptions:
    AccessError - the given token is not valid and does not refer to any authenticated user
Return Value:
    Returns a list of dictionaries each of which contains the dm_id and name of the DM that the user is a member of.

'''
def dm_list_v1(token):
    dm_return_list = []
    check_token(token)
    data = data_store.get()
    target_user = data['users'][user_from_token(token) - 1]
    for dm in data['dms']:
        if target_user in (dm['owner_members'] + dm['all_members']):
            dm_return_list.append({'dm_id' : dm['dm_id'], 'name' : dm['name']})
    return {"dms" : dm_return_list}


# Implementation for dm/remove/v1
'''
Remove a DM such that all members are no longer in the DM. This can only be done by the original creator of the DM.
Arguments:
    token (string) - a string of a potentially authenticated JWT which when decoded reveals a user's id number and the session id.
    dm_id (integer) - integer which contains an potentially valid id for a dm
Exceptions:
    InputError - when the given dm_id does not refer to a valid dm in the data store
    AccessError - when the user tied to a valid token is not a member of the dm associated to the valid dm_id
    AccessError - when the token passed into the function does not refer to a valid user
Return Value:
    Returns an empty dictionary

'''
def dm_remove_v1(token, dm_id):
    # Check the validity of the token
    check_token(token)
    data = data_store.get()
    # Check the validity of the dm_id
    if dm_id < 0 or dm_id > len(data['dms']):
        raise InputError(f"{dm_id} does not refer to a valid dm")
    target_user = user_from_token(token)
    target_dm = data['dms'][dm_id]

    # Check that the token refers to the original creator of the dm.
    # If it does, remove the dm and change the ids of those behind it in the list
    if target_user == target_dm['creator_id']:
        target_dm['owner_members'].clear()
        target_dm['all_members'].clear()

    # Otherwise raise an access error
    else:
        raise AccessError(description="user is not the original creator of the dm")
    return {}


# Implementation for dm/leave/v1
'''
Given a valid token and dm_id, have the user tied to the token leave the dm associated with dm_id. Raises an input error if the dm_id
is invalid. Raises an access error if the token is invalid or the user is not a member of the dm

Arguments:
    token (string) - a string of a potentially authenticated JWT which when decoded reveals a user's id number and the session id.
    dm_id (integer) - integer which contains an potentially valid id for a dm
Exceptions:
    InputError - when the given dm_id does not refer to a valid dm in the data store
    AccessError - when the user tied to a valid token is not a member of the dm associated to the valid dm_id
    AccessError - when the token passed into the function does not refer to a valid user
Return Value:
    Returns an empty dictionary

'''
def dm_leave_v1(token, dm_id):
    # Check the validity of the token
    check_token(token)
    data = data_store.get()
    # Check the validity of the dm_id
    if dm_id < 0 or dm_id > len(data['dms']):
        raise InputError(description="invalid dm id")
    # Check that the user tied to the token is a member of the dm
    target_user = data['users'][user_from_token(token) - 1]
    target_dm = data['dms'][dm_id]
    if target_user in target_dm['owner_members']:
        target_dm['owner_members'].remove(target_user)
    elif target_user in target_dm['all_members']:
        target_dm['all_members'].remove(target_user)
    else:
        raise AccessError(description="user is not a member of dm and thus cannot leave it")
    data = data_store.get()
    return {}


# Implementation for dms/messages/v1
'''
Given a DM with ID dm_id that the authorised user is a member of, return up to 50 messages between index "start" and "start + 50".
Message with index 0 is the most recent message in the channel. This function returns a new index "end" which is the value of "start + 50", or,
if this function has returned the least recent messages in the channel, returns -1 in "end"
to indicate there are no more messages to load after this return.
Arguments:
    token (string) - a string of a already verified JWT which when decoded reveals a user's id number and the session id.
    dm_id (integer) - integer of an potentially valid id that refers to a dm
    start (integer) - integer refering to the start index of the messages list for the given dm
Exceptions:
    AccessError - the token passed into the function is invalid (i.e has a payload with an invalid user id or session id)
    AccessError - the token passed into the function refers to a valid user but they are not a member of the given dm
    InputError - the dm_id passed into the function does not refer to a valid dm
    InputError - the start index passed into the function is greater than the number of messages in the dm
Return Value:
    Returns a dictionary contaning a list of messages, the new start index and the end index.

'''
def dm_messages_v1(token, dm_id, start):
    # Check the validity of token
    check_token(token)
    data = data_store.get()
    # Check the validity of the dm_id
    if dm_id < 0 or dm_id > len(data['dms']):
        raise InputError(description='id does not refer to a valid dm')

    # Check that the user from the token is a member of the dm
    target_user = data['users'][user_from_token(token) - 1]
    dm = data['dms'][dm_id]
    all_members = dm['all_members'] + dm['owner_members']
    if target_user not in all_members:
        raise AccessError(description='user is not a member of dm')

    # Check the start index is not greater than the number of messages
    if start == 0 and len(dm['messages']) == 0:
        return {'messages' : [], 'start' : start, 'end' : -1}
    if start > len(dm['messages']) -1:
        raise InputError(description=f'there are less than {start} messages in dm')

    # get start + 50 messages
    messages = dm['messages'][start : start + 50]
    # Reverse the list so that the most recent message is at the beginning of the list and remove the default element
    messages.reverse()
    end = start + 50
    if start + 50  >= len(dm['messages']):
        end = -1
    return {'messages' : messages, 'start' : start, 'end' : end}
