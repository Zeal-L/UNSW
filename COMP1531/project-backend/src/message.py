###############################################################################
# Message_Implementation for COMP1531, Iteration 3. Written by Dev Chopra for
# W13A, group Beagle.
###############################################################################

#############################################
# Import(s)
#############################################
from src.data_store import data_store
from src.error import InputError, AccessError
from src.helper import  check_token, \
                        check_valid_channel_id, \
                        decode_jwt, \
                        check_message_length, \
                        user_from_token, \
                        check_valid_message_id, \
                        find_message, \
                        check_react_id

from datetime import datetime
from string import digits
import time
from string import punctuation
#############################################
# Constant
#############################################

INT_MIN = -2147483648


def message_send_v1(token, channel_id, message):
    '''
    <This function sends a message from user with the given token to the given channel in channel_id>

    Arguments:
        <token> (<String>)    - <Token contains the jwt for the user sending the request>
        <channel_id> (<Integer>)    - <Channel id contains the id of the channel that the message is being sent to>
        <message> (<String>)    - <Message contains a string which holds the message that is being sent>

    Exceptions:
        InputError  - Occurs when channel_id does not refer to a valid channel
        InputError  - Occurs when message is less then 1 character or greater then 1000 characters
        AccessError - Occurs when channel_id is valid but the user is not a member of the channel
        AccessError - Occurs when token is invalid

    Return Value:
        Returns the message id on successful operation
    '''
    # Check validity of token
    check_token(token)

    # Check validity of channel ID
    check_valid_channel_id(channel_id)

    # Check the length of the message
    check_message_length(message)

    # Get data store to start working on it
    store = data_store.get()

    # Get authorised user's id
    u_id = decode_jwt(token)['u_id']

    # By default the user is unauthorised
    unauthorised_user = True

    # Iterate through the channels and users to see whether the user is authorised
    for channel in store["channels"]:
        if channel_id == channel['channel_id']:
            for user in channel["owner_members"]:
                if user["u_id"] == u_id:
                    unauthorised_user = False
                    break
            for user in channel["all_members"]:
                if user["u_id"] == u_id:
                    unauthorised_user = False
                    break

    # If user is unauthorised show an appropriate error
    if unauthorised_user:
        raise AccessError(description = "channel_id is valid but the user given is unauthorised")

    # Get the length of all messages and use this for our id
    message_id = len(store['messages']) + len(store['later_messages'])

    # Check for any user tags in the message
    handles = []
    for u in store['users']:
        handles.append(u['handle_str'])
    tags = []
    for w in message.split():
        word = w.translate(str.maketrans('', '', punctuation)) # remove punctuation from the word
        if word in handles and word not in tags: 
            tags.append(word)
    for t in tags:
        u_handle = str(store['users'][u_id-1]['handle_str'])
        channel_name = str(store['channels'][channel_id]['name'])
        notification_message = u_handle + ' tagged you in ' + channel_name + ': ' + message[: 21]
        for u in store['users']:
            if t ==  u['handle_str']:
                u['notifications'].append({
                    'channel_id' : channel_id,
                    'dm_id' : -1,
                    'notification_message' : notification_message
                })

    # Append the new message to the channel's messages
    channel['messages'].append({'message_id' : message_id,'u_id' : u_id,'message' : message,'time_created' : datetime.now().strftime('%d/%m/%Y, %H:%M:%S'), 'reacts' : [], 'is_pinned' : False})

    # Append a key value pair of the message id and channel id for quick channel lookup
    store['messages'].append({message_id : [channel_id, 'channel'], 'u_id' : u_id})

    # Return message_id
    return {'message_id' : message_id}

def message_edit_v1(token, message_id, message):
    '''
    <This function replaces a previous message with new text given that the user sending the request is authorised>

    Arguments:
        <token> (<String>)    - <Token contains the jwt for the user sending the request>
        <message_id> (<Integer>)    - <message_id contains the id of the message that is being edited>
        <message> (<String>)    - <Message contains a string which holds the message that is going to replace the previous message>

    Exceptions:
        InputError  - Occurs when message_id does not refer to a valid message
        InputError  - Occurs when message is greater then 1000 characters
        AccessError - Occurs when message_id is valid but the user is not the one who sent it OR if the user is not an owner of the dm/channel
        AccessError - Occurs when token is invalid

    Return Value:
        Returns an empty dictionary on successful operation
    '''
    # Check validity of token
    check_token(token)

    # Check the length of the message
    if len(message) > 1000:
        raise InputError(description = "Message length is greater then 1000")

    # Get data store to start working on it
    store = data_store.get()

    # Get authorised user's id
    u_id = decode_jwt(token)['u_id']

    # Check validity of message ID
    check_valid_message_id(message_id, u_id)

    # By default the user is unauthorised
    error_condition_one = True

    # Check whether the message is in a channel or a dm
    channel_or_dm = store['messages'][message_id]
    channel_or_dm = channel_or_dm[message_id][1]
    # If the user has permission to edit the message then break and not show the error condition
    if channel_or_dm == "channel":
        for channel in store["channels"]:
            for user in channel["owner_members"]:
                if user["u_id"] == u_id:
                    error_condition_one = False
                    break
            for original_message in channel["messages"]:
                if original_message["u_id"] == u_id:
                    error_condition_one = False
                    break
    else:
        for channel in store["dms"]:
            for user in channel["owner_members"]:
                if user["u_id"] == u_id:
                    error_condition_one = False
                    break
            for original_message in channel["messages"]:
                if original_message["u_id"] == u_id and original_message["message_id"] == message_id:
                    error_condition_one = False
                    break

    # If user is still unauthorised show an appropriate error
    if error_condition_one:
        raise AccessError(description = "message_id is valid but the user given is unauthorised")

    # Edit message to new message
    original_message['message'] = message

    # Return empty dictionary
    return {}

def message_remove_v1(token, message_id):
    '''
    <This function deletes a message given that the user is authorised>

    Arguments:
        <token> (<String>)    - <Token contains the jwt for the user sending the request>
        <message_id> (<Integer>)    - <message_id contains the id of the message that is being edited>

    Exceptions:
        InputError  - Occurs when message_id does not refer to a valid message
        AccessError - Occurs when message_id is valid but the user is not the one who sent it OR if the user is not an owner of the dm/channel
        AccessError - Occurs when token is invalid

    Return Value:
        Returns an empty dictionary on successful operation
    '''
    # Check validity of token
    check_token(token)

    # Get authorised user's id
    u_id = decode_jwt(token)['u_id']

    # Check validity of message ID
    check_valid_message_id(message_id, u_id)

    # Get data store to start working on it
    store = data_store.get()

    # By default the user is unauthorised
    unauthorised_user = True

    # Check whether the message is in a channel or a dm
    channel_or_dm = store['messages'][message_id]
    channel_or_dm_id = channel_or_dm[message_id][0]
    channel_or_dm = channel_or_dm[message_id][1]

    # If the user has permission to edit the message then break and not show the error condition
    if channel_or_dm == "channel":
        for channel in store["channels"]:
            if channel['channel_id'] == channel_or_dm_id:
                for user in channel["owner_members"]:
                    if user["u_id"] == u_id:
                        unauthorised_user = False
                        break
                for message in channel["messages"]:
                    if message["u_id"] == u_id and message["message_id"] == message_id:
                        unauthorised_user = False
                        break
    else:
        for channel in store["dms"]:
            if channel['dm_id'] == channel_or_dm_id:
                if channel["owner_members"][0]["u_id"] == u_id:
                    unauthorised_user = False
                for message in channel["messages"]:
                    if message["u_id"] == u_id and message["message_id"] == message_id:
                        unauthorised_user = False
                        break

    # If user is still unauthorised show an appropriate error
    if unauthorised_user:
        raise AccessError(description = "message_id is valid but the user given is unauthorised")

    # Delete the given message
    channel["messages"].remove(message)
    store['messages'][message_id] = [INT_MIN, "N/A"]
    # Return an empty dictionary
    return {}

'''
Given a valid token, and dm_id, send a message to the DM tied to the id.

Arguments:
    token (string) - a JWT which when decoded refers to a potentially authorised user with a valid session
    dm_id (integer) - an integer of an id that potentially refers to a valid DM
    message (string) - a string contaningn the acutal message to be sent
Exceptions:
    AccessError - if the given token does not refer to an authorised user with a valid session
    AccessError - if the given user is not a member of the dm
    InputError -  if the given dm_id is not valid
    InputError - if the given message is not of a valid length
Return Value:
    Returns a dictionary contannig the id of the newly created message
'''
# Implementation for message/senddm/v1
def message_senddm_v1(token, dm_id, message):
    # Check the validity of the token
    check_token(token)
    data = data_store.get()
    # Check the validity of the dm id
    if dm_id < 0 or dm_id > len(data['dms']):
        raise InputError(description="not a valid dm")
    # Check the membership of the user associated with the token
    u_id = user_from_token(token)
    target_user = data['users'][u_id-1]
    members = data['dms'][dm_id]['owner_members'] + data['dms'][dm_id]['all_members']
    if target_user not in members:
        raise AccessError(description="user is not a member of dm")
    # Check the validity of the message
    if len(message) < 1 or len(message) > 1000:
        raise InputError(description="invalid message length, either an empty message was sent or input was too long")

    handles = []
    for u in data['users']:
        handles.append(u['handle_str'])
    
    handles = []
    for u in data['users']:
        handles.append(u['handle_str'])
    tags = []
    for w in message.split():
        word = w.translate(str.maketrans('', '', punctuation)) # remove punctuation from the word
        if word in handles and word not in tags: 
            tags.append(word)
    for t in tags:
        u_handle = str(data['users'][u_id-1]['handle_str'])
        dm_name = str(data['dms'][dm_id]['name'])
        notification_message = u_handle + ' tagged you in ' + dm_name + ': ' + message[: 21]
        for u in data['users']:
            if t ==  u['handle_str']:
                u['notifications'].append({
                    'channel_id' : -1,
                    'dm_id' : dm_id,
                    'notification_message' : notification_message
                })
        
    # If eveything is good, send the message and append a new message to
    m_id = len(data['messages']) + len(data['later_messages'])
    data['dms'][dm_id]['messages'].append(
        {
        'message_id' : m_id,
        'u_id' : user_from_token(token),
        'message' : message,
        'time_created' : datetime.now().strftime('%d/%m/%Y, %H:%M:%S'),
        'reacts' : [],
        'is_pinned' : False
        }
    )
    data['messages'].append({m_id : [dm_id, 'dm'], 'u_id' : u_id})
    return {"message_id" : m_id}

'''
Given an authorised user, react and a message. The function will add a react for that user onto a message.

Arguments:
    token (string) - a string of a already verified JWT which when decoded reveals a user's id number and the session id.
    message_id (integer) - the id for the message that is being reacted to
    react_id (string) - the id of the react that is being added to the message

Exceptions:
    InputError - message_id is not a valid message within a channel or DM that the authorised user has joined
    InputError - react_id is not a valid react ID
    InputError - the message already contains a react with ID react_id from the authorised user
    AccessError - Invalid token given to the function

Return Value:
    Returns an empty dictionary on successful return.
'''
def message_react_v1(token, message_id, react_id):
    # Check validity of token
    check_token(token)

    # Get authorised user's id
    u_id = decode_jwt(token)['u_id']
    # Check validity of message ID
    check_valid_message_id(message_id, u_id)
    # Check validity of the react
    check_react_id(react_id)

    # Get data store to start working on it
    store = data_store.get()

    # Check whether the message is in a channel or a dm
    channel_or_dm = store['messages'][message_id]
    channel_or_dm_id = channel_or_dm[message_id][0]
    channel_or_dm = channel_or_dm[message_id][1]
    notify = False
    sender = ''
    handle = ''
    notification_message = ''
   # Iterate and find the message for which to add a react to.
    if channel_or_dm == "channel":
        for channel in store["channels"]:
            if channel['channel_id'] == channel_or_dm_id:
                for message in channel["messages"]:
                    if message["message_id"] == message_id:
                        for react in message["reacts"]:
                            if react["react_id"] == react_id:
                                # If the react exists already we check for the user, if the user does not exist in the react we add the user
                                if u_id in react["u_ids"]:
                                    raise InputError("the message already contains a react with ID react_id from the authorised user") 
                                react["u_ids"].append(u_id)
                                sender = message['u_id']
                                handle = store['users'][u_id-1]['handle_str']
                                name = store['channels'][channel_or_dm_id]['name']
                                notification_message = handle + ' reacted to your message in ' + name
                                store['users'][sender-1]['notifications'].append(
                                    {
                                        'channel_id' : channel_or_dm_id,
                                        'dm_id' : -1,
                                        'notification_message' : notification_message
                                    }
                                )
                                if message["u_id"] == u_id:
                                    react["is_this_user_reacted"] = True
                                return {}
                        # If the react does not exist we create it
                        message["reacts"].append({"react_id": react_id, "u_ids": [u_id], "is_this_user_reacted": False})
                        # send the notification
                        notify = True
                        if message["u_id"] == u_id:
                            for react in message["reacts"]:
                                if react["react_id"] == react_id:
                                    react["is_this_user_reacted"] = True
    
                            break
        if notify:
            sender = message['u_id']
            handle = store['users'][u_id-1]['handle_str']
            name = store['channels'][channel_or_dm_id]['name']
            notification_message = handle + ' reacted to your message in ' + name
            store['users'][sender-1]['notifications'].append(
                {
                    'channel_id' : channel_or_dm_id,
                    'dm_id' : -1,
                    'notification_message' : notification_message
                }
            )

    else: 
        for channel in store["dms"]:
            if channel['dm_id'] == channel_or_dm_id:
                for message in channel["messages"]:
                    if message["message_id"] == message_id:
                        for react in message["reacts"]:
                            if react["react_id"] == react_id:
                                # If the react exists already we check for the user, if the user does not exist in the react we add the user
                                if u_id in react["u_ids"]:
                                    raise InputError("the message already contains a react with ID react_id from the authorised user") 
                                react["u_ids"].append(u_id)
                                sender = message['u_id']
                                handle = store['users'][u_id-1]['handle_str']
                                name = store['dms'][channel_or_dm_id]['name']
                                notification_message = handle + ' reacted to your message in ' + name
                                store['users'][sender-1]['notifications'].append(
                                    {
                                        'channel_id' : -1,
                                        'dm_id' : channel_or_dm_id,
                                        'notification_message' : notification_message
                                    }
                                )
                                if message["u_id"] == u_id:
                                    react["is_this_user_reacted"] = True
                                return {}
                        # If the react does not exist we create it
                        message["reacts"].append({"react_id": react_id, "u_ids": [u_id], "is_this_user_reacted": False})
                        # send the notification
                        sender = message['u_id']
                        handle = store['users'][u_id-1]['handle_str']
                        name = store['dms'][channel_or_dm_id]['name']
                        notification_message = handle + ' reacted to your message in ' + name
                        store['users'][sender-1]['notifications'].append(
                            {
                                'channel_id' : -1,
                                'dm_id' : channel_or_dm_id,
                                'notification_message' : notification_message
                            }
                        )
                        if message["u_id"] == u_id:
                            for react in message["reacts"]:
                                if react["react_id"] == react_id:
                                    react["is_this_user_reacted"] = True
                        break

    return {}


'''
Given an authorised user, react and a message. The function will remove a react for that user from that message.

Arguments:
    token (string) - a string of a already verified JWT which when decoded reveals a user's id number and the session id.
    message_id (integer) - the id for the message that is having the react removed
    react_id (string) - the id of the react that is being removed from the message

Exceptions:
    InputError - message_id is not a valid message within a channel or DM that the authorised user has joined
    InputError - react_id is not a valid react ID
    InputError - the message does not contain a react with ID react_id from the authorised user
    AccessError - Invalid token given to the function

Return Value:
    Returns an empty dictionary on successful return.
'''
def message_unreact_v1(token, message_id, react_id):
    # Check validity of token
    check_token(token)

    # Get authorised user's id
    u_id = decode_jwt(token)['u_id']

    # Check validity of message ID
    check_valid_message_id(message_id, u_id)

    # Check validity of the react
    check_react_id(react_id)

    # Get data store to start working on it
    store = data_store.get()

    # Check whether the message is in a channel or a dm
    channel_or_dm = store['messages'][message_id]
    channel_or_dm_id = channel_or_dm[message_id][0]
    channel_or_dm = channel_or_dm[message_id][1]

    # By default the message does not contain a react
    react_doesnt_exist = True

    # Iterate and find the message for which to add a react to.
    if channel_or_dm == "channel":
        for channel in store["channels"]:
            if channel['channel_id'] == channel_or_dm_id:
                for message in channel["messages"]:
                    if message["message_id"] == message_id:
                        for react in message["reacts"]:
                            if react["react_id"] == react_id:
                                # If the react is found we set the flag to False and remove the user from the react
                                react_doesnt_exist = False
                                if u_id in react["u_ids"]:
                                    react["u_ids"].remove(u_id)
                                    if message["u_id"] == u_id:
                                        react["is_this_user_reacted"] = False
                                    if react["u_ids"] == []:
                                        message["reacts"].remove(react)
                                    break
    else: 
        for channel in store["dms"]:
            if channel['dm_id'] == channel_or_dm_id:
                for message in channel["messages"]:
                    if message["message_id"] == message_id:
                        for react in message["reacts"]:
                            if react["react_id"] == react_id:
                                # If the react is found we set the flag to False and remove the user from the react
                                react_doesnt_exist = False
                                if u_id in react["u_ids"]:
                                    react["u_ids"].remove(u_id)
                                    if message["u_id"] == u_id:
                                        react["is_this_user_reacted"] = False
                                    if react["u_ids"] == []:
                                        message["reacts"].remove(react)
                                    break
    if react_doesnt_exist:
        raise InputError("the message does not contain a react with ID react_id from the authorised user")
    return {}
    
'''
Given an authorised user and a message. The function will pin the given message.

Arguments:
    token (string) - a string of a already verified JWT which when decoded reveals a user's id number and the session id.
    message_id (integer) - the id for the message that is being pinned

Exceptions:
    InputError - message_id is not a valid message within a channel or DM that the authorised user has joined
    InputError - The message is already pinned
    AccessError - message_id refers to a valid message in a joined channel/DM and the authorised user does not have owner permissions in the channel/DM
    AccessError - Invalid token given to the function

Return Value:
    Returns an empty dictionary on successful return.
'''
def message_pin_v1(token, message_id):
    # Check validity of token
    check_token(token)

    # Get authorised user's id
    u_id = decode_jwt(token)['u_id']

    # Check validity of message ID
    check_valid_message_id(message_id, u_id)
    
    # Get data store to start working on it
    store = data_store.get()

    # By default the user is unauthorised
    authorised_user = False

    
    # Check whether the message is in a channel or a dm
    channel_or_dm = store['messages'][message_id]
    channel_or_dm_id = channel_or_dm[message_id][0]
    channel_or_dm = channel_or_dm[message_id][1]

    # Check that the user has owner permissions by iterating through the channel/dm
    if channel_or_dm == "channel":
        for channel in store["channels"]:
            if channel['channel_id'] == channel_or_dm_id:
                for user in channel["owner_members"]:
                    if user["u_id"] == u_id:
                        authorised_user = True
                        break
    else:
        for channel in store["dms"]:
            if channel['dm_id'] == channel_or_dm_id:
                for user in channel["owner_members"]:
                    if user["u_id"] == u_id:
                        authorised_user = True
                        break
    
    # Check if user is a global streams owner if not an owner of the channel
    if authorised_user == False:
        for user in store["users"]:
            if user["u_id"] == u_id:
                if user['permission_id'] == 1:
                    authorised_user = True
                    break

    if authorised_user == False:
        raise AccessError("message_id refers to a valid message in a joined channel/DM and the authorised user does not have owner permissions in the channel/DM")

    # If this code block is reached, the user is authorised and we iterate through the data store to find the message to pin.
    if channel_or_dm == "channel":
        for channel in store["channels"]:
            if channel['channel_id'] == channel_or_dm_id:
                for message in channel["messages"]:
                    if message["message_id"] == message_id:
                        if message["is_pinned"] == True:
                            raise InputError("the message is already pinned")
                        else:
                            message["is_pinned"] = True
    else:
        for channel in store["dms"]:
            if channel['dm_id'] == channel_or_dm_id:
                for message in channel["messages"]:
                    if message["message_id"] == message_id:
                        if message["is_pinned"] == True:
                            raise InputError("the message is already pinned")
                        else:
                            message["is_pinned"] = True
    
    return {}
    
'''
Given an authorised user and a message. The function will unpin the given message.

Arguments:
    token (string) - a string of a already verified JWT which when decoded reveals a user's id number and the session id.
    message_id (integer) - the id for the message that is being unpinned

Exceptions:
    InputError - message_id is not a valid message within a channel or DM that the authorised user has joined
    InputError - The message is not pinned
    AccessError - message_id refers to a valid message in a joined channel/DM and the authorised user does not have owner permissions in the channel/DM
    AccessError - Invalid token given to the function

Return Value:
    Returns an empty dictionary on successful return.
'''
def message_unpin_v1(token, message_id):
    # Check validity of token
    check_token(token)

    # Get authorised user's id
    u_id = decode_jwt(token)['u_id']

    # Check validity of message ID
    check_valid_message_id(message_id, u_id)
    
    # Get data store to start working on it
    store = data_store.get()

    # By default the user is unauthorised
    authorised_user = False
    
    # Check whether the message is in a channel or a dm
    channel_or_dm = store['messages'][message_id]
    channel_or_dm_id = channel_or_dm[message_id][0]
    channel_or_dm = channel_or_dm[message_id][1]

    # Check that the user has owner permissions by iterating through the channel/dm
    if channel_or_dm == "channel":
        for channel in store["channels"]:
            if channel['channel_id'] == channel_or_dm_id:
                for user in channel["owner_members"]:
                    if user["u_id"] == u_id:
                        authorised_user = True
                        break
    else:
        for channel in store["dms"]:
            if channel['dm_id'] == channel_or_dm_id:
                for user in channel["owner_members"]:
                    if user["u_id"] == u_id:
                        authorised_user = True
                        break
    
    # Check if user is a global streams owner if not an owner of the channel
    if authorised_user == False:
        for user in store["users"]:
            if user["u_id"] == u_id:
                if user['permission_id'] == 1:
                    authorised_user = True
                    break

    if authorised_user == False:
        raise AccessError("message_id refers to a valid message in a joined channel/DM and the authorised user does not have owner permissions in the channel/DM")

    # If this code block is reached, the user is authorised and we iterate through the data store to find the message to pin.
    if channel_or_dm == "channel":
        for channel in store["channels"]:
            if channel['channel_id'] == channel_or_dm_id:
                for message in channel["messages"]:
                    if message["message_id"] == message_id:
                        if message["is_pinned"] == False:
                            raise InputError("the message is not already pinned")
                        else:
                            message["is_pinned"] = False
    else:
        for channel in store["dms"]:
            if channel['dm_id'] == channel_or_dm_id:
                for message in channel["messages"]:
                    if message["message_id"] == message_id:
                        if message["is_pinned"] == False:
                            raise InputError("the message is not already pinned")
                        else:
                            message["is_pinned"] = False
    
    return {}   

# Implementation for message/share/v1
'''
Share a message to another channel or dm that the user is a part of. The message can be shared with a supplementary message
that can be an empty string.
Arguments:
    token (string) - a JWT which when decoded refers to a potentially authorised user with a valid session.
    og_message_id (integer) - an id referring to the original message that will be shared to another channel/dm
    message (string) - a string contaningn the acutal message to be sent
    channel_id (integer) - an id that refers to a potentially valid channel or -1 if the message is being shared to a dm
    dm_id (integer) - an integer of an id that potentially refers to a valid DM or -1 if the message is being shared to a channel

Exceptions:
    AccessError - if the given token does not refer to an authorised user with a valid session
    AccessError - if the user is not a member of the channel/dm that they are trying to share a message to
    InputError - if both the supplied channel_id and dm_id are invalid
    InputError -  if the given dm_id and channel_id are both -1
    InputError - if the og_message_id does not refer to a valid message
    InputError - if the supplementary message is not of a valid length
Return Value:
    Returns a dictionary contannig the id of the shared message
'''
def message_share_v1(token, og_message_id, message, channel_id, dm_id):
    # check token,
    # check validity of channel_id and dm_id
    # check the values of channel_id and dm_id (both are not -1)
    # check og_message_id (does it refer to a message in a channel/dm that the user is a part of)
    # check the length of message (is it > 1000 characters)

    # given a valid pair of ids, check that the non -1 id refers to a target channel/dm that the 
    # user is a member of

    check_token(token)
    data = data_store.get()
    
    id = user_from_token(token)
    user = data['users'][id-1]
    
    if (channel_id < 0 or channel_id > len(data['channels'])) and (dm_id < 0 or dm_id > len(data['dms'])):
        raise InputError(description='Both channel and dm ids are invalid')

    if channel_id != -1 and dm_id != -1:
        raise InputError(description='Both id values are -1. Only one can be -1')

    # check the messages within the channels or dms that the user is a part of
    og_message = find_message(user, og_message_id)
    
    if len(message) > 1000:
        raise InputError(description='supplementary message is too long - must be less than 1000 characters')
    
    m_id = len(data['messages']) + len(data['later_messages']) 
    if channel_id != -1:
        members = data['channels'][channel_id]['owner_members'] + data['channels'][channel_id]['all_members']
        if user in members:
            data['channels'][channel_id]['messages'].append({
                'message_id' : m_id,
                'u_id' : id,
                'message' : og_message['message'] + message,
                'time_created' : datetime.now().strftime('%d/%m/%Y, %H:%M:%S'),
                'reacts' : [],
                'is_pinned' : False
            })
        else:
            raise AccessError(description='user is not a member of the channel that the message is being shared to')

    elif dm_id != -1:
        members = data['dms'][dm_id]['owner_members'] + data['dms'][dm_id]['all_members']
        if user in members:
            data['dms'][dm_id]['messages'].append({
                'message_id' : m_id,
                'u_id' : id,
                'message' : og_message['message'] + message,
                'time_created' : datetime.now().strftime('%d/%m/%Y, %H:%M:%S'),
                'reacts' : [],
                'is_pinned' : False
            })
        else:
            raise AccessError(description='user is not a member of the dm that the message is being shared to')
    return {'shared_message_id' : m_id}

# Implementation for message/sendlater/v1
'''
Schedule a message to be sent to a channel at a later time in the future.
Arguments:
    token (string) - a JWT which when decoded refers to a potentially authorised user with a valid session
    channel_id (integer) - an id that refers to a potentially valid channel
    message (string) - a string contaningn the acutal message to be sent
    time_sent (integer) - unix epoch time that the message will be sent at
Exceptions:
    AccessError - if the given token does not refer to an authorised user with a valid session
    AccessError - if the user is not a member of the channel that they are trying to share a message to
    InputError - if the supplied channel id is invalid
    InputError - if the supplementary message is not of a valid length
    InputError - if the time scheduled to send the message is in the past
Return Value:
    Returns a dictionary contannig the id of the message scheduled to send at a later time
'''
def message_sendlater_v1(token, channel_id, message, time_sent):
    # check the token
    check_token(token)
    data = data_store.get()
    u_id = user_from_token(token)
    user = data['users'][u_id - 1]

    if channel_id < 0 or channel_id > len(data['channels']):
        raise InputError(description='invalid channel id')

    channel = data['channels'][channel_id]
    if user not in channel['all_members'] + channel['owner_members']:
        raise AccessError(description='given user is not a member of the channel')
    
    if len(message) <= 0 or len(message) > 1000:
        raise InputError(description='message is not of a valid length')
    if time_sent < int(time.time()):
        raise InputError(description='cannot schedule a message to be send in the past')

    m_id = len(data['later_messages']) + len(data['messages'])
    data['later_messages'].append(
        {
            'message_id' : m_id,
            'token' : token,
            'channel/dm_id' : channel_id,
            'message' : message,
            'time_sent' : time_sent,
            'reacts' : [],
            'is_pinned' : False,
            'channel/dm' : 'channel'
        }
    )
    return {'message_id' : m_id}

# Implementation for message/sendlater/v1
'''
Schedule a message to be sent to a dm at a later time in the future.
Arguments:
    token (string) - a JWT which when decoded refers to a potentially authorised user with a valid session
    dm_id (integer) - an id that refers to a potentially valid dm
    message (string) - a string contaningn the acutal message to be sent
    time_sent (integer) - unix epoch time that the message will be sent at
Exceptions:
    AccessError - if the given token does not refer to an authorised user with a valid session
    AccessError - if the user is not a member of the dm that they are trying to share a message to
    InputError - if the supplied dm id is invalid
    InputError - if the supplementary message is not of a valid length
    InputError - if the time scheduled to send the message is in the past
Return Value:
    Returns a dictionary contannig the id of the message scheduled to send at a later time
'''
def message_sendlaterdm_v1(token, dm_id, message, time_sent):
    check_token(token)
    data = data_store.get()
    u_id = user_from_token(token)
    user = data['users'][u_id - 1]

    if dm_id < 0 or dm_id > len(data['dms']):
        raise InputError(description='invalid dm id')

    dm = data['dms'][dm_id]
    if user not in dm['all_members'] + dm['owner_members']:
        raise AccessError(description='given user is not a member of the dm')
    
    if len(message) <= 0 or len(message) > 1000:
        raise InputError(description='message is not of a valid length')
    if time_sent < int(time.time()):
        raise InputError(description='cannot schedule a message to be send in the past')

    m_id = len(data['later_messages']) + len(data['messages'])
    data['later_messages'].append(
        {
            'message_id' : m_id,
            'token' : token,
            'channel/dm_id' : dm_id,
            'message' : message,
            'time_sent' : time_sent,
            'reacts' : [],
            'is_pinned' : False,
            'channel/dm' : 'dm'
        }
    )
    return {'message_id' : m_id}