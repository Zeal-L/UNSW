from src.data_store import data_store
from src.error import InputError, AccessError
from src.helper import check_valid_channel_id, check_token, decode_jwt, check_if_member
from src.message import message_send_v1
import threading
import time

def standup_start_v1(token, channel_id, length):
    '''
    <For a given channel, start the standup period whereby for the next "length" seconds
        if someone calls "standup/send" with a message, it is buffered during
        the X second window then at the end of the X second window a message
        will be added to the message queue in the channel from the user
        who started the standup. "length" is an integer that denotes the number of seconds
        that the standup occurs for.>

    Arguments:
        <token> (<String>) - <The token of a streams user.>
        <channel_id> (<integer>) - <The channel identification number.>
        <length> (<integer>) - <seconds if someone calls "standup/send" with a message,.>

    Exceptions:
        InputError - channel_id does not refer to a valid channel
        InputError - length is a negative integer
        InputError - an active standup is currently running in the channel

        AccessError - channel_id is valid and the authorised user is not a member of the channel
        AccessError - When token is not valid.

    Return Value:
        Returns nothing.
    '''

    check_token(token)
    check_valid_channel_id(channel_id)
    if isinstance(length, int):
        if length < 0:
            raise InputError("length is a negative integer")
    else:
        raise InputError("length is not an integer")

    store = data_store.get()
    target_channel = {}
    for channel in store["channels"]:
        if channel["channel_id"] == channel_id:
            target_channel = channel

    if target_channel["standup_active"] == True:
        raise InputError("an active standup is currently running in the channel")

    u_id = decode_jwt(token)['u_id']
    if not check_if_member(channel_id, u_id):
        raise AccessError("channel_id is valid and the authorised user is not a member of the channel")


    target_channel["standup_active"] = True
    target_channel["standup_queue"] = []

    standup_window = threading.Timer(length, standup_end, kwargs={'token' : token, 'target_channel' : target_channel})
    standup_window.start()

    time_finish = int(time.time()) + length
    target_channel["time_finish"] = time_finish
    return {'time_finish' : time_finish}

def standup_end(**kw):
    for message in kw['target_channel']["standup_queue"]:
        message_send_v1(kw['token'], kw['target_channel']['channel_id'], message)
    kw['target_channel']["standup_active"] = False
    kw['target_channel']["standup_queue"] = []
    kw['target_channel']["time_finish"] = None

def standup_active_v1(token, channel_id):
    '''
    <For a given channel, return whether a standup is active in it,
        and what time the standup finishes. If no standup is active,
        then time_finish returns None.>

    Arguments:
        <token> (<String>) - <The token of a streams user.>
        <channel_id> (<integer>) - <The channel identification number.>

    Exceptions:
        InputError - channel_id does not refer to a valid channel

        AccessError - channel_id is valid and the authorised user is not a member of the channel
        AccessError - When token is not valid.

    Return Value:
        Returns nothing.
    '''

    check_token(token)
    check_valid_channel_id(channel_id)

    u_id = decode_jwt(token)['u_id']
    if not check_if_member(channel_id, u_id):
        raise AccessError("channel_id is valid and the authorised user is not a member of the channel")

    store = data_store.get()
    target_channel = {}
    for channel in store["channels"]:
        if channel["channel_id"] == channel_id:
            target_channel = channel

    if target_channel["standup_active"] == False:
        return {
            'is_active' : False,
            'time_finish' : None
        }
    else:
        return {
            'is_active' : True,
            'time_finish' : target_channel["time_finish"]
        }


def standup_send_v1(token, channel_id, message):
    '''
    <Sending a message to get buffered in the standup queue, assuming a standup is
        currently active. Note: We do not expect @ tags to be parsed as proper tags
        when sending to standup/send>

    Arguments:
        <token> (<String>) - <The token of a streams user.>
        <channel_id> (<integer>) - <The channel identification number.>
        <message> (<String>) - <message.>

    Exceptions:
        InputError - channel_id does not refer to a valid channel
        InputError - length of message is over 1000 characters
        InputError - an active standup is not currently running in the channel

        AccessError - channel_id is valid and the authorised user is not a member of the channel
        AccessError - When token is not valid.

    Return Value:
        Returns nothing.
    '''

    check_token(token)
    check_valid_channel_id(channel_id)

    u_id = decode_jwt(token)['u_id']
    if not check_if_member(channel_id, u_id):
        raise AccessError("channel_id is valid and the authorised user is not a member of the channel")

    store = data_store.get()
    target_channel = {}
    for channel in store["channels"]:
        if channel["channel_id"] == channel_id:
            target_channel = channel

    if target_channel["standup_active"] == False:
        raise InputError("an active standup is not currently running in the channel")

    if len(message) > 1000:
        raise InputError("length of message is over 1000 characters")

    target_channel["standup_queue"].append(message)