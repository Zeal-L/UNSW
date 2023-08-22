# Written by Raffaele Hughes (z5349314) on 27/09/2021 for the group W13A_Beagle

# Import Statements
from src.data_store import data_store
from src.error import InputError, AccessError
from src.helper import decode_jwt, check_token, SECRET

# Global Constants
INT_MIN = -2147483648


# Funtions
'''
Attempts to create a channel with the given name and publicity. The user tied to the token is considered
the channel creator and automatically joins it

Arguments:
    <token> - string - <A JWT of a potentially valid Streams user>

Exceptions:
    AccessError - When the given token does not refer to a valid user id and sesion id when decoded.
    InputError - The length of the channels's name is either less than 1 character or greather than 20

Return Value:
    Returns a dictionary containing the newly created channel's id number
'''
def channels_create_v2(token, name, is_public):
    # Need to raise an InputError if 1 > len(name) or len(name) > 20
    if len(name) < 1 or len(name) > 20:
        raise InputError(description="Invalid channel name, must be between 1 and 20 characters long")
    # Authenticate the token and decode it to get a user id
    check_token(token)
    store = data_store.get()
    user_id = decode_jwt(token)['u_id']

    add_user = {}
    for user in store['users']:
        if user['u_id'] == user_id:
            add_user = user.copy()

    # Create the new channel using the information passed into the function.
    # Additionally, get the user associated with auth_user_id and append them to the owner_members list.
    c_id = len(store['channels'])
    store['channels'].append({
        'name'          : name,
        'channel_id'    : c_id,
        'is_public'     : is_public,
        'owner_members' : [add_user],
        'all_members'   : [add_user],
        'messages'      : [],
        'standup_active': False,
        'standup_queue' : [],
        'time_finish'   : None
    })
    # Return the new channel's id as a dictionary
    return {"channel_id" : c_id}

'''
List every channel in UNSW Streams regardless of its privacy status and their associated details.

Arguments:
    <token> - string - <A JWT of a potentially valid Streams user>

Exceptions:
    AccessError - When the given token does not refer to a valid user id and sesion id when decoded.

Return Value:
    Returns a dictionary a list of channels. Each element in the list is a dictionary which contains the id number and name
    of each channel in UNSW streams
'''
def channels_listall_v2(token):
    # Authenticate the token
    check_token(token)
    data = data_store.get()
    channels_list = []
    # Exclude the first channel since that is our default entry with INT_MIN
    for channel in data["channels"]:
        channels_list.append(
            {
                "channel_id" : channel["channel_id"],
                "name" : channel["name"]
            }
        )
    return {"channels" : channels_list}

'''
Given a token which refers to a user, return a list of all channels that they are a member of

Arguments:
    <token> - string - <A JWT of a potentially valid Streams user>

Exceptions:
    AccessError - When the given token does not refer to a valid user id and sesion id when decoded.
Return Value:
    Returns a dictionary a list of channels. Each element in the list is a dictionary which contains the id number and name
    of each channel that the given user is a member of
'''
def channels_list_v2(token):
    # Authenticate the token and extract the user id
    check_token(token)
    data = data_store.get()
    u_id = decode_jwt(token)['u_id']
    user = data['users'][u_id - 1]
    channel_list = []
    # Iterate through each channel in the data store and check if the user is a member
    for channel in data['channels']:
        members_list = channel['owner_members'] + channel['all_members']
        if user in members_list:
            channel_list.append({
                'channel_id' : channel['channel_id'],
                'name' : channel['name']
            })
    return {'channels' : channel_list}
