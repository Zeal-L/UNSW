###############################################################################
# Channel_Implementation for COMP1531, Iteration 3. Written by Jordan Terzian,
# Zeal Liang and Dev Chopra for W13A, group Beagle.
###############################################################################

#############################################
# Import(s)
#############################################
from src.data_store import data_store
from src.error import InputError, AccessError
from src.helper import check_channel_publicity, \
                        check_if_owner, \
                        check_token, \
                        check_valid_channel_id, \
                        decode_jwt, \
                        check_valid_auth_user_id, \
                        check_if_member
from tests.admin_test import GLOBAL_OWNERS, MEMBERS

def channel_invite_v2(token, channel_id, u_id):
    '''
    <Invites a user with ID u_id to join a channel with ID channel_id. Once invited, the user is added to the channel immediately.>

    Arguments:
        <token> (<String>) - <The jwt of an existing channel member. Required to authorise channel invites>
        <channel_id> (<Integer>) - <The specific channels' identification number>
        <u_id> (<Integer>) - <The invite receiving users' identification number>

    Exceptions:
        InputError  - Occurs when channel_id does not refer to a valid channel.
        InputError  - When u_id does not refer to a valid user.
        InputError  - When u_id refers to a user who is already a member of the channel. (all_members)
        InputError  - When u_id refers to a user who is already a member of the channel. (owner_members)
        AccessError - When token does not refer to a valid user.
        AccessError - When channel_id is valid and the authorised user is not a member of the channel.

    Return Value:
        Function returns an empty dictionary
    '''
    # Get the data store
    store = data_store.get()

    ###ACCESS ERRORS###

    # Check that Token is valid
    check_token(token)


    ###INPUT ERRORS###
    # Check to see if channel_id does not refer to valid channel
    check_valid_channel_id(channel_id)

    # Check to see if user is valid
    flag = True
    for user in store["users"]:
        if user["u_id"] == u_id:
            flag = False
    if flag:
        raise InputError(description = "u_id does not refer to a valid user")

    # Check to see if user is already (owner) in channel
    for channel in store["channels"]:
        if channel['channel_id'] == channel_id:
            for user in channel['owner_members']:
                if user["u_id"] == u_id:
                    raise InputError(description = "u_id refers to a user who is already a member of the channel")

    # Check to see if user is already (member) in channel
    for channel in store["channels"]:
        if channel['channel_id'] == channel_id:
            for user in channel['all_members']:
                if user["u_id"] == u_id:
                    raise InputError(description = "u_id refers to a user who is already a member of the channel")


    ###ACCESS ERRORS###

    # Check to see if authorised user is not a member of the channel
    authorised_user_id = decode_jwt(token)['u_id']
    checker = True
    for channel in store["channels"]:
        if channel['channel_id'] == channel_id:
            for user in channel['all_members']:
                if user["u_id"] == authorised_user_id:
                    checker = False
            for user in channel['owner_members']:
                if user["u_id"] == authorised_user_id:
                    checker = False
    if checker == True:
        raise AccessError(description = "The authorised user is not a member of the channel")


    # Adds user to channel if channel_id is valid
    add_user = {}
    for user in store['users']:
        if user['u_id'] == u_id:
            add_user = user.copy()

    for channel in store["channels"]:
        if channel["channel_id"] == channel_id:
                     channel["all_members"].append(add_user)
    
    # Send add_user a notification
    handle = store['users'][authorised_user_id-1]['handle_str']
    notification_message = str(handle) + ' added you to ' + store['channels'][channel_id]['name']
    store['users'][u_id - 1]['notifications'].append({
        'channel_id' : channel_id,
        'dm_id' : -1,
        'notification_message' : notification_message
    })
    return {}


def channel_details_v2(token, channel_id):
    '''
    <When this function is given a valid channel ID and is accompanied by an authorised user's token, the channels' details are returned>

    Arguments:
        <token> (<String>) - <The token of a pre-existing channel member.>
        <channel_id> (<Integer>) - <The specific channels' identification number>

    Exceptions:
        InputError  - Occurs when channel_id does not refer to a valid channel.
        AccessError - When token does not refer to a valid user.
        AccessError - When channel_id is valid and the authorised user is not a member of the channel.

    Return Value:
        Returns a dictionary containing channel details. The dictionary contains the channel name as a string, whether the channel is public as a boolean,
        a list of owner members and a list of all members.
    '''
    # Get the data store
    store = data_store.get()

    # Check that auth_user_id is valid
    check_token(token)
    # Check that channel_id is valid
    check_valid_channel_id(channel_id)

    # Decode token into user_id
    auth_user_id = decode_jwt(token)['u_id']

    # By default, the user is unauthorised
    unauthorised_user = True

    # Iterate through the data store to check whether the user is authorised to access the details of the channel
    for channel_list in store["channels"]:
        if channel_id == channel_list["channel_id"]:
            for user in channel_list["all_members"]:
                if auth_user_id == user["u_id"]:
                    unauthorised_user = False
                    break
            for user in channel_list["owner_members"]:
                if auth_user_id == user["u_id"]:
                    unauthorised_user = False
                    break

    # Show an error that the user is unauthorised if the user is not a member of the channel
    if unauthorised_user:
        raise AccessError(description = "The authorised user is not a member of the channel")

    # Set up the initial return value
    ret_value = {
        "name" : channel_list["name"],
        "is_public" : channel_list["is_public"],
        "owner_members" : [],
        "all_members" : []
    }
    # Go through owner members and copy over to return_value without their passwords
    for channel_list in store["channels"]:
        if channel_id == channel_list["channel_id"]:
            for member in channel_list["owner_members"]:
                new_member = member.copy()
                del new_member['password']
                ret_value["owner_members"].append(new_member)

    # Go through all members and copy over to return_value without their passwords
    for channel_list in store["channels"]:
        if channel_id == channel_list["channel_id"]:
            for member in channel_list["all_members"]:
                new_member = member.copy()
                del new_member['password']
                ret_value["all_members"].append(new_member)

    # Return this value
    return ret_value


def channel_messages_v2(token, channel_id, start):
    '''
    <When this function is given a valid channel ID and is accompanied by an authorised user's token, the channels' messages are returned.>

    Arguments:
        <token> (<String>) - <The user token of a pre-existing channel member.>
        <channel_id> (<Integer>) - <The specific channel's identification number>
        <start> (<Integer>) - <The starting index for messages to be returned with 0 being the most recent message>

    Exceptions:
        InputError  - Occurs when channel_id does not refer to a valid channel.
        InputError  - Occurs when start is greater than the total number of messages in the channel.
        AccessError - When token does not refer to a valid user.
        AccessError - When channel_id is valid and the authorised user is not a member of the channel.

    Return Value:
        Returns a dictionary containing channel messages. The dictionary contains a list of messages, the start index and an end index.
    '''
    # Get the data store
    store = data_store.get()

    return_value = {
        'messages' : [],
        'start' : start,
        'end' : 0
    }
    # Check if token is valid
    check_token(token)
    # Check if channel_id is valid
    check_valid_channel_id(channel_id)

    # Decode token into user_id
    auth_user_id = decode_jwt(token)['u_id']

    # By default, the user is unauthorised
    unauthorised_user = True

    # Go through channels and check whether the user is authorised to access the messages
    for channel in store['channels']:
        if (channel['channel_id'] == channel_id):
            messages_length = len(channel['messages'])
            for user in channel["owner_members"]:
                if auth_user_id == user["u_id"]:
                    unauthorised_user = False
                    break
            for user in channel["all_members"]:
                if auth_user_id == user["u_id"]:
                    unauthorised_user = False
                    break

    # Show an error that the user is unauthorised if the user is not a member of the channel
    if unauthorised_user:
        raise AccessError(description = "The authorised user is not a member of the channel")

    # Check the number of messages, if start is greater then number of messages show an error
    if (start) > messages_length:
        raise InputError(description = "Start is greater than the total number of messages in the channel")
    else:
        for begin in range(start, start + 50):
            if len(channel['messages']) == 0:
                return_value['end'] = -1
                break

            return_value["messages"].append(channel["messages"][begin])
            return_value['end'] = begin

            if (begin + 1) >= messages_length:
                return_value['end'] = -1
                break

    return return_value


def channel_join_v2(token, channel_id):
    '''
    <Given a channel_id of a channel that the authorised user can join, adds them to that channel.>

    Arguments:
        <token> (<String>) - <The jwt of a pre-existing channel member.>
        <channel_id> (<Integer>) - <The specific channels identification number>

    Exceptions:
        InputError  - Occurs when channel_id does not refer to a valid channel.
        InputError  - The authorised user is already a member of the channel
        AccessError - When channel_id refers to a channel that is private and the authorised user is not already a channel member and is not a global owner

    Return Value:
        Function returns an empty dictionary

    '''
    # Get the data store
    store = data_store.get()

    # Return u_id from a given token
    u_id = decode_jwt(token)['u_id']


    ###INPUT ERRORS###

    # Check to see if channel_id does not refer to valid channel
    check_valid_channel_id(channel_id)


    # Check to see if user is already in channel
    if (check_if_member(channel_id, u_id) == True):
        raise InputError(description = "The authorised user is already a member of the channel")


    ###ACCESS ERRORS###

    # Function to check valid token
    check_token(token)

    add_user = {}
    for user in store['users']:
        if user['u_id'] == u_id:
            add_user = user.copy()

    # Check to see if Channel is private and auth_user is not a global owner or a channel member
    if(check_channel_publicity(channel_id) == False and check_if_owner(u_id, channel_id) == False and check_if_member(channel_id, u_id) == False):
        raise AccessError(description = "channel_id refers to a channel that is private and the authorised user is not a global owner or a channel member")


    # If channel is private and auth_user is a global owner and not already in channel, add user to channel
    elif(check_channel_publicity(channel_id) == False and check_if_owner(u_id, channel_id) == True and check_if_member(channel_id, u_id) == False):
        for channel in store["channels"]:
            if channel["channel_id"] == channel_id:
                channel["owner_members"].append(add_user)


    # Adds user to channel if channel_id is valid
    for channel in store["channels"]:
        if channel["channel_id"] == channel_id:
            channel["all_members"].append(add_user)

    return {}


'''
<Given a channel with ID channel_id that the authorised user is a member of, remove them as a member of the channel.>

Arguments:
    <token> (<String>)    - <Holds the users informatin>
    <channel_id> (<Integer>) - <The specific channels' identification number>

Exceptions:
    InputError  - Occurs when channel_id does not refer to a valid channel
    AccessError - Occurs when channel_id is valid and the authorised user is not a member of the channel
    AccessError - When the token is invalid
Return Value:
    Function returns an empty dictionary
'''

def channel_leave_v1(token, channel_id):

    # Get the data store
    store = data_store.get()

    u_id = decode_jwt(token)['u_id']

    ###INPUT ERRORS###
    # Check to see if channel_id does not refer to valid channel
    check_valid_channel_id(channel_id)


    ###ACCESS ERRORS###

    # Check to see that token is valid
    check_token(token)

    # Check to see if authorised user is not a member of the channel
    checker = True
    for channel in store["channels"]:
        if channel['channel_id'] == channel_id:
            for user in channel['owner_members']:
                if user["u_id"] == u_id:
                    checker = False
            for user in channel['all_members']:
                if user["u_id"] == u_id:
                    checker = False

    if checker:
        raise AccessError(description = "The authorised user is not a member of the channel")

    # Remove owner from channel
    if (check_if_owner(u_id, channel_id) == True):
        for channel in store["channels"]:
            for user in channel["owner_members"]:
                if user["u_id"] == u_id:
                    channel["owner_members"].remove(user)

    # Remove a user from channel
    else:
        for channel in store["channels"]:
            for user in channel["all_members"]:
                if user["u_id"] == u_id:
                    channel["all_members"].remove(user)
    return {}

def channel_add_owner_v1(token, channel_id, u_id):
    '''
    <Given a channel with ID channel_id that the authorised user is an owner of, add a given user as owner.>

    Arguments:
        <token> (<String>)    - <The jwt for the authorised user>
        <channel_id> (<Integer>) - <The identification number for a channel>
        <u_id> (<Integer>) - <The identification number for a given user>

    Exceptions:
        InputError  - Occurs when channel_id does not refer to a valid channel
        InputError  - Occurs when u_id does not refer to a valid user
        InputError  - Occurs when u_id refers to a user who is not a member of the given channel
        InputError  - Occurs when u_id refers to a user who is already an owner of the channel
        AccessError - Occurs when channel_id is valid and the authorised user does not have permissions to add an owner
        AccessError - When the token is invalid

    Return Value:
        Function returns an empty dictionary
    '''
    # Get the data store
    store = data_store.get()

    # By default, the authorised_user is unauthorised and the given user is not a member of the channel
    unauthorised_user = True
    user_given_not_member = True

    # Check that token is valid
    check_token(token)
    # Check that channel_id is valid
    check_valid_channel_id(channel_id)
    #Check that u_id is valid
    check_valid_auth_user_id(u_id)

    # Decode owner id from jwt
    owner = decode_jwt(token)['u_id']

    # Create temporary dictionary to hold the user that will be made owner
    user_to_change = {}
    target_channel = {}
    # Iterate through channels and channel members to see if the given user is a member of the channel to be made owner
    for channel in store["channels"]:
        if channel_id == channel["channel_id"]:
            target_channel = channel
            for user in channel["all_members"]:
                if user['u_id'] == u_id:
                    user_to_change = user
                    user_given_not_member = False
                    break

    # If user is already an owner then raise an input error highlighting this
    for user in target_channel["owner_members"]:
        if user['u_id'] == u_id:
            raise InputError(description = "User is already an owner of the channel")

    # Check that the authorised_user has permission to add an owner to the channel
    for user in target_channel["owner_members"]:
        if user['u_id'] == owner:
            unauthorised_user = False
            break

    for user in store['users']:
        if user['u_id'] == owner:
            if user['permission_id'] == GLOBAL_OWNERS:
                for u in channel["all_members"]:
                    if u['u_id'] == owner:
                        unauthorised_user = False
                break


    # Show appropriate error message if required
    if unauthorised_user:
        raise AccessError(description = "Channel_id is valid but the authorised user is not an owner of the channel/streams")
    if user_given_not_member:
        raise InputError(description = "The user given is not a member of this channel")


    # Add user as owner and return empty dictionary
    target_channel["all_members"].remove(user_to_change)
    target_channel["owner_members"].append(user_to_change)
    return {}

def channel_remove_owner_v1(token, channel_id, u_id):
    '''
    <Given a channel with ID channel_id that the authorised user is an owner of, remove a given user as owner.>

    Arguments:
        <token> (<String>)    - <The jwt for the authorised user>
        <channel_id> (<Integer>) - <The identification number for a channel>
        <u_id> (<Integer>) - <The identification number for a given user>

    Exceptions:
        InputError  - Occurs when channel_id does not refer to a valid channel
        InputError  - Occurs when u_id does not refer to a valid user
        InputError  - Occurs when u_id refers to a user who is not an owner of the given channel
        InputError  - Occurs when u_id refers to the only owner of the channel
        AccessError - Occurs when channel_id is valid and the authorised user does not have permissions to remove an owner
        AccessError - When the token is invalid

    Return Value:
        Function returns an empty dictionary
    '''
    # Get the data store
    store = data_store.get()

    # By default, the authorised_user is unauthorised and the given user is not an owner of the channel
    unauthorised_user = True
    user_given_not_owner = True

    # Check that token is valid
    check_token(token)
    # Check that channel_id is valid
    check_valid_channel_id(channel_id)
    #Check that u_id is valid
    check_valid_auth_user_id(u_id)

    # Decode the jwt for the owner into the id
    owner = decode_jwt(token)['u_id']

    # Store the user_to_change in a temp dictionary
    user_to_change = {}

    # Iterate through channels and channel members to see if the given user is an owner in the channel
    for channel in store["channels"]:
        if channel_id == channel["channel_id"]:
            for user in channel["owner_members"]:
                if user['u_id'] == u_id:
                    user_to_change = user
                    user_given_not_owner = False
                    break

    # Check if the user is the only owner of the channel
    for user in channel["owner_members"]:
        if user['u_id'] == u_id and len(channel["owner_members"]) == 1:
            raise InputError(description = "user is currently the only owner of the channel")

    # Check that the authorised_user has permission to add an owner to the channel
    for user in channel["owner_members"]:
        if user['u_id'] == owner:
            unauthorised_user = False
            break
    for user in store['users']:
        if user['u_id'] == owner:
            if user['permission_id'] == 1:
                unauthorised_user = False
                break

    # Show appropriate error message if required
    if unauthorised_user:
        raise AccessError(description = "Channel_id is valid but the authorised user is not an owner of the channel/streams")
    if user_given_not_owner:
        raise InputError(description = "The user given is not an owner of this channel")


    # Remove user as owner and return an empty dictionary
    channel["all_members"].append(user_to_change)
    channel["owner_members"].remove(user_to_change)
    return {}