from tests.admin_test import GLOBAL_OWNERS, MEMBERS
from src.data_store import data_store
from src.error import InputError, AccessError
from src.helper import check_valid_u_id, check_only_global_owner, check_global_owner, check_token, decode_jwt

def admin_user_remove_v1(token, u_id):
    '''
    <Given a user by their u_id, remove them from the Streams.>

    Arguments:
        <token> (<String>) - <The token of a streams user.>
        <u_id> (<integer>) - <The user identification number.>

    Exceptions:
        InputError - Then the u_id passed in is not valid"
        InputError - u_id refers to a user who is the only global owner
        AccessError - when the authorised user is not a global owner
        AccessError - When token is not valid.

    Return Value:
        Returns nothing.
    '''

    check_valid_u_id(u_id)
    check_global_owner(decode_jwt(token)['u_id'])
    check_only_global_owner(u_id)
    check_token(token)

    # name_first should be 'Removed' and name_last should be 'user'.
    # The user's email and handle should be reusable.
    store = data_store.get()
    for user in store["users"]:
        if user["u_id"] == u_id:
            user['name_first'] = 'Removed'
            user['name_last'] = 'user'
            user['email'] = ''
            user['handle_str'] = ''
            user['password'] = ''
            user['permission_id'] = ''
    # User info removed from all channels
    # and messages user sent changed to 'Removed user'
    for channel in store["channels"]:
        for user in channel["owner_members"]:
            if user['u_id'] == u_id:
                channel["owner_members"].remove(user)
        for user in channel["all_members"]:
            if user['u_id'] == u_id:
                channel["all_members"].remove(user)
        for message in channel["messages"]:
            if message['u_id'] == u_id:
                message['message'] = 'Removed user'

    # User info removed from all DMs
    # and messages user sent changed to 'Removed user'
    for dm in store['dms']:
        for user in dm["owner_members"]:
            if user['u_id'] == u_id:
                dm["owner_members"].remove(user)
        for user in dm["all_members"]:
            if user['u_id'] == u_id:
                dm["all_members"].remove(user)
        for message in dm["messages"]:
            if message['u_id'] == u_id:
                message['message'] = 'Removed user'



def admin_userpermission_change_v1(token, u_id, permission_id):
    '''
    <Given a user by their user ID, set their permissions
        to new permissions described by permission_id.>

    Arguments:
        <token> (<String>) - <The token of a streams user.>
        <u_id> (<integer>) - <The user identification number.>
        <permission_id> (<integer>) - <The user permission_id number.>

    Exceptions:
        InputError - Then the u_id passed in is not valid"
        InputError - u_id refers to a user who is the only global owner and they are being demoted to a user
        InputError - when permission_id is invalid
        AccessError - when the authorised user is not a global owner
        AccessError - When token is not valid.

    Return Value:
        Returns nothing.
    '''

    check_valid_u_id(u_id)
    check_only_global_owner(u_id)
    check_global_owner(decode_jwt(token)['u_id'])
    check_token(token)

    if permission_id not in (GLOBAL_OWNERS, MEMBERS):
        raise InputError("permission_id is invalid")

    store = data_store.get()
    for user in store["users"]:
        if user["u_id"] == u_id:
            user["permission_id"] = permission_id
