#############################################
# Import(s)
#############################################

import pytest
import requests
import json
from src import config
from src.helper import generate_jwt
from tests.requests import *

#############################################
# Constant(s)
#############################################

INVALID_TOKEN = generate_jwt(-1,-1)
INVALID_ID = -1


#############################################
# Initial setup (Reset state of application)
#############################################

@pytest.fixture(scope="function")
def setup():
    requests.delete(config.url + 'clear/v1')
    # Register first user
    first_user = json.loads(post_register('validemail@gmail.com', '123abc!@#', 'Hayden', 'Everest').text)
    # Register second user
    second_user = json.loads(post_register('anotheremail@gmail.com', '123abc4534!@#', 'Michael', 'Jackson').text)

    json.loads(post_channels_create(first_user['token'], "DJ Khaled Fan Club", True).text)
    # Create New Channel
    new_channel = json.loads(post_channels_create(first_user['token'], "channel", True).text)

    return {'first_user' : first_user, 'second_user' : second_user, 'new_channel' : new_channel}

#############################################
# channel_invite_v2 Tests
#############################################

# Test that an AccessError is returned when there is a authorised user
# id is not valid in the chat
def test_channel_invite_invalid_auth_user_id(setup):
    assert post_channel_invite(INVALID_TOKEN,
                                setup['new_channel']['channel_id'],
                                setup['second_user']['auth_user_id']).status_code == ACCESSERROR

# Test that an InputError is returned when channel_id does not refer to a valid
# channel
def test_channel_invite_invalid_channel_id(setup):
    assert post_channel_invite(setup['first_user']['token'],
                                INVALID_ID,
                                setup['second_user']['auth_user_id']).status_code == INPUTERROR

# Test that an InputError is returned when u_id does not refer to a valid user
def test_invalid_uid(setup):
    assert post_channel_invite(setup['first_user']['token'],
                                setup['new_channel']['channel_id'],
                                INVALID_TOKEN).status_code == INPUTERROR


# Test that an InputError is returned when u_id refers to a user who is already
# a member of the channel
def test_uid_already_member(setup):
    assert post_channel_invite(setup['first_user']['token'],
                                setup['new_channel']['channel_id'],
                                setup['first_user']['auth_user_id']).status_code == INPUTERROR

# Test that an InputError is returned when u_id refers to a user who is already
# a member of the channel
def test_uid_already_member_2(setup):
    post_channel_invite(setup['first_user']['token'],
                                setup['new_channel']['channel_id'],
                                setup['second_user']['auth_user_id'])
    assert post_channel_invite(setup['first_user']['token'],
                                setup['new_channel']['channel_id'],
                                setup['second_user']['auth_user_id']).status_code == INPUTERROR

# Test that an AccessError is returned when the authorised user is not a member
# of the channel
def test_channel_invite_unauthorised_user(setup):
    assert post_channel_invite(setup['second_user']['token'],
                                setup['new_channel']['channel_id'],
                                setup['second_user']['auth_user_id']).status_code == ACCESSERROR

# Test that when all conditions are met a user can be invited and added to the
# channel as per the spec
def test_valid_channel_invite(setup):
    assert post_channel_invite(
                setup['first_user']['token'],
                setup['new_channel']['channel_id'],
                setup['second_user']['auth_user_id']).status_code not in (INPUTERROR, ACCESSERROR)
    third_user = json.loads(post_register('anotheremail3@gmail.com', '123abc4534!@#', 'ZiYi', 'Liang').text)
    assert post_channel_invite(
                setup['second_user']['token'],
                setup['new_channel']['channel_id'],
                third_user['auth_user_id']).status_code not in (INPUTERROR, ACCESSERROR)
    fourth_user = json.loads(post_register('anotheremail4@gmail.com', '123abc4534!@#', 'Kevin', 'Liang').text)
    assert post_channel_invite(
                third_user['token'],
                setup['new_channel']['channel_id'],
                fourth_user['auth_user_id']).status_code not in (INPUTERROR, ACCESSERROR)


#############################################
# channel_details_v2 Tests
#############################################

# Test that an AccessError is returned when there is a authorised user
# id is not valid in the chat
def test_channel_details_invalid_auth_user_id(setup):
        assert get_channel_details(INVALID_TOKEN,
                                    setup['new_channel']['channel_id']).status_code == ACCESSERROR

# Test that an InputError is returned when channel_id does not refer to a valid
# channel
def test_channel_details_invalid_channel_id(setup):
    assert get_channel_details(setup['first_user']['token'],
                                INVALID_ID).status_code == INPUTERROR

# Test that an AccessError is returned when the authorised user is not a member
# of the channel
def test_channel_details_unauthorised_user(setup):
    assert(get_channel_details(setup['second_user']['token'],
                                setup['new_channel']['channel_id']).status_code == ACCESSERROR)

# Test that when all conditions are met basic details of channel are provided as
# per spec
def test_valid_channel_details(setup):
    # Returns as tuple
    post_channel_invite(
                setup['first_user']['token'],
                setup['new_channel']['channel_id'],
                setup['second_user']['auth_user_id'])
    third_user = json.loads(post_register('anotheremail3@gmail.com', '123abc4534!@#', 'ZiYi', 'Liang').text)
    post_channel_invite(setup['second_user']['token'], setup['new_channel']['channel_id'], third_user['auth_user_id'])
    details = json.loads(get_channel_details(third_user['token'], setup['new_channel']['channel_id']).text)
    assert details["name"] == "channel"
    assert details["is_public"] == True
    assert details["owner_members"][0]['u_id'] == 1
    assert details["owner_members"][0]['email'] == 'validemail@gmail.com'
    assert details["owner_members"][0]['name_first'] == 'Hayden'
    assert details["owner_members"][0]['name_last'] == 'Everest'
    assert details["owner_members"][0]['handle_str'] == 'haydeneverest'


#############################################
# channel_messages_v2 Tests
#############################################

# Test that an AccessError is returned when there is a authorised user
# id is not valid in the chat
def test_channel_messages_invalid_auth_user_id(setup):
    assert get_channel_messages(INVALID_TOKEN, setup['new_channel']['channel_id'], 0).status_code == ACCESSERROR

# Test that an InputError is returned when the channel_id does not refer to a
# valid channel
def test_channel_messages_invalid_channel_id(setup):
        assert get_channel_messages(setup['first_user']['token'], INVALID_ID, 0).status_code == INPUTERROR

# Test that an InputError is returned when the start is greater than the total
# number of messages in the channel
def test_start_greater_then_total(setup):
        assert get_channel_messages(setup['first_user']['token'],
                                    setup['new_channel']['channel_id'], 5000000).status_code == INPUTERROR

# Test that an AccessError is returned when the authorised user is not a member
# of the channel
def test_channel_messages_unauthorised_user(setup):
    assert get_channel_messages(setup['second_user']['token'],
                                setup['new_channel']['channel_id'], 0).status_code == ACCESSERROR

# Test the channel_messages returns messages as per spec
def test_valid_channel_messages(setup):
    # Return as dict (end is equal to start + 50 or -1 depending on if there
    # are new messages or not.
    messages = json.loads(get_channel_messages(setup['first_user']['token'],
                                                setup['new_channel']['channel_id'], -1).text)
    assert messages["messages"] == []
    assert messages["start"] == -1
    assert messages["end"] == -1

# Test the channel_messages returns only 50 messages
def test_valid_channel_messages_more_then_50(setup):
    for i in range(55):
        post_message_send(setup['first_user']['token'], setup['new_channel']['channel_id'], str(i))
    messages = json.loads(get_channel_messages(setup['first_user']['token'],
                                                setup['new_channel']['channel_id'], 0).text)
    assert len(messages['messages']) == 50

#############################################
# channel_join_v2 Tests
#############################################

# Test that an AccessError is returned when an authorised user is not a global
# owner
def test_channel_join_invalid_auth_user_id(setup):
    assert post_channel_join(INVALID_TOKEN,
                            setup['new_channel']['channel_id']).status_code == ACCESSERROR

# Test that an InputError is returned when channel_id does not refer to a valid
# channel
def test_channel_join_invalid_channel_id(setup):
    assert post_channel_join(setup['first_user']['token'], INVALID_ID).status_code == INPUTERROR

# Test that an InputError is returned when an authorised user is already a
# channel member
def test_existing_user_channel_join(setup):
    assert post_channel_join(setup['first_user']['token'],
                            setup['new_channel']['channel_id']).status_code == INPUTERROR

# Test than an AccessError is returned when a private_channel is accessed by
# a non-authorised user
def test_private_channel_channel_join(setup):
    private_channel = json.loads(post_channels_create(setup['first_user']['token'], "channel", False).text)
    assert post_channel_join(setup['second_user']['token'],
                            private_channel['channel_id']).status_code == ACCESSERROR

# Test that when all conditions are met a private channel can be joined by a global owner
def test_private_channel_channel_join_success(setup):
    private_channel = json.loads(post_channels_create(setup['second_user']['token'], "channel", False).text)
    assert post_channel_join(setup['first_user']['token'],
                            private_channel['channel_id']).status_code not in (INPUTERROR, ACCESSERROR)

# Test that If user is already member of channel
def test_valid_channel_already_join(setup):
    assert post_channel_join(setup['second_user']['token'],
                            setup['new_channel']['channel_id']).status_code not in (INPUTERROR, ACCESSERROR)
    assert post_channel_join(setup['second_user']['token'],
                            setup['new_channel']['channel_id']).status_code == INPUTERROR


# Test that when all conditions are met a channel can be joined as per spec
def test_valid_channel_join(setup):
    assert post_channel_join(setup['second_user']['token'],
                            setup['new_channel']['channel_id']).status_code not in (INPUTERROR, ACCESSERROR)
    third_user = json.loads(post_register('anotheremail3@gmail.com', '123abc4534!@#', 'ZiYi', 'Liang').text)
    assert post_channel_join(third_user['token'],
                            setup['new_channel']['channel_id']).status_code not in (INPUTERROR, ACCESSERROR)

#############################################
# channel_leave_v1 Tests
#############################################

# Test that the request throws an input error when channel_id does not refer to a valid channel
def test_invalid_channel_id_channel_leave(setup):
    assert post_channel_leave(setup['first_user']['token'], INVALID_ID).status_code == INPUTERROR

# Test that the request throws an access error when the authorised user is not a member of the channel
def test_user_is_not_member_channel_leave(setup):
    assert post_channel_leave(setup['second_user']['token'],
                            setup['new_channel']['channel_id']).status_code == ACCESSERROR

# Test that the request throws an access error when an invalid token is given
def test_token_invalid_channel_leave(setup):
    assert post_channel_leave(INVALID_TOKEN,
                            setup['new_channel']['channel_id']).status_code == ACCESSERROR

# Test that the user has successfully left the channel when authorised user is in owner_members
def test_channel_leave_valid_owner(setup):
    post_channel_invite(setup['first_user']['token'],
                        setup['new_channel']['channel_id'],
                        setup['second_user']['auth_user_id'])
    third_user = json.loads(post_register('anotheremail3@gmail.com', '123abc4534!@#', 'ZiYi', 'Liang').text)
    post_channel_invite(setup['first_user']['token'],
                        setup['new_channel']['channel_id'],
                        third_user['auth_user_id'])
    post_channel_add_owner(setup['first_user']['token'], setup['new_channel']['channel_id'], third_user['auth_user_id'])
    assert post_channel_leave(third_user['token'],
                            setup['new_channel']['channel_id']).status_code not in (ACCESSERROR,INPUTERROR)
    owners = json.loads(get_channel_details(setup['second_user']['token'],
                                            setup['new_channel']['channel_id']).text)['owner_members']
    for owner in owners:
        assert third_user['auth_user_id'] != owner['u_id']

# Test that the user has successfully left the channel when authorised user is in all_members
def test_channel_leave_valid_members(setup):
    post_channel_invite(setup['first_user']['token'],
                        setup['new_channel']['channel_id'],
                        setup['second_user']['auth_user_id'])
    third_user = json.loads(post_register('anotheremail3@gmail.com', '123abc4534!@#', 'ZiYi', 'Liang').text)
    post_channel_invite(setup['first_user']['token'],
                        setup['new_channel']['channel_id'],
                        third_user['auth_user_id'])
    assert post_channel_leave(third_user['token'],
                            setup['new_channel']['channel_id']).status_code not in (ACCESSERROR,INPUTERROR)
    owners = json.loads(get_channel_details(setup['first_user']['token'],
                                            setup['new_channel']['channel_id']).text)['owner_members']
    for owner in owners:
        assert third_user['auth_user_id'] != owner['u_id']


#############################################
# channel_add_owner_v1 Tests
#############################################

# Test that the request throws an input error when channel_id does not refer to a valid channel
def test_invalid_channel_id_channel_add_owner(setup):
    assert post_channel_add_owner(setup['first_user']['token'],
                                INVALID_ID,
                                setup['second_user']['auth_user_id']).status_code == INPUTERROR

# Test that the request throws an input error when u_id does not refer to a valid user
def test_invalid_uid_channel_add_owner(setup):
    assert post_channel_add_owner(setup['first_user']['token'],
                                setup['new_channel']['channel_id'], INVALID_ID).status_code == INPUTERROR

# Test that the request throws an input error when user who is not a member of the channel is being made owner
def test_u_id_not_member_channel_add_owner(setup):
    assert post_channel_add_owner(setup['first_user']['token'],
                                setup['new_channel']['channel_id'],
                                setup['second_user']['auth_user_id']).status_code == INPUTERROR

# Test that the request throws an input error when the user is already an owner
def test_u_id_already_owner_channel_add_owner(setup):
    assert post_channel_add_owner(setup['first_user']['token'],
                                setup['new_channel']['channel_id'],
                                setup['first_user']['auth_user_id']).status_code == INPUTERROR

# Test that the request throws an access error when the channel is valid but the authorised user does not have owner permissions
def test_authorised_user_is_not_owner_channel_add_owner(setup):
    post_channel_invite(setup['first_user']['token'],
                        setup['new_channel']['channel_id'],
                        setup['second_user']['auth_user_id'])
    assert post_channel_add_owner(setup['second_user']['token'],
                                setup['new_channel']['channel_id'],
                                setup['second_user']['auth_user_id']).status_code == ACCESSERROR

# Test that the request throws an access error when an invalid token is given
def test_invalid_token_channel_add_owner(setup):
    post_channel_invite(setup['first_user']['token'],
                        setup['new_channel']['channel_id'],
                        setup['second_user']['auth_user_id'])
    assert post_channel_add_owner(INVALID_TOKEN,
                                setup['new_channel']['channel_id'],
                                setup['second_user']['auth_user_id']).status_code == ACCESSERROR

# Test that the request has worked properly
def test_valid_channel_add_owner(setup):
    post_channel_invite(setup['first_user']['token'],
                        setup['new_channel']['channel_id'],
                        setup['second_user']['auth_user_id'])
    assert post_channel_add_owner(setup['first_user']['token'],
                                setup['new_channel']['channel_id'],
                                setup['second_user']['auth_user_id']) not in (INPUTERROR, ACCESSERROR)
    owners = json.loads(get_channel_details(setup['second_user']['token'],
                                            setup['new_channel']['channel_id']).text)['owner_members']
    new_owner_not_found = False
    for owner in owners:
        if owner['u_id'] == setup['second_user']['auth_user_id']:
            new_owner_not_found = True
    assert new_owner_not_found

# Test that the request has worked properly with global owner
def test_valid_channel_global_owner_can_add_owner(setup):
    new_channel = json.loads(post_channels_create(setup['second_user']['token'], "channel321", True).text)
    post_channel_invite(setup['second_user']['token'],
                        new_channel['channel_id'],
                        setup['first_user']['auth_user_id'])
    assert post_channel_add_owner(setup['first_user']['token'],
                                new_channel['channel_id'],
                                setup['first_user']['auth_user_id']) not in (INPUTERROR, ACCESSERROR)


#############################################
# channel_remove_owner_v1 Tests
#############################################

# Test that the request throws an input error when channel_id does not refer to a valid channel
def test_invalid_channel_id_channel_remove_owner(setup):
    assert post_channel_remove_owner(setup['first_user']['token'],
                                    INVALID_ID,
                                    setup['second_user']['auth_user_id']).status_code == INPUTERROR

# Test that the request throws an input error when u_id does not refer to a valid user
def test_invalid_u_id_channel_remove_owner(setup):
    assert post_channel_remove_owner(setup['first_user']['token'],
                                    setup['new_channel']['channel_id'],
                                    INVALID_ID).status_code == INPUTERROR

# Test that the request throws an input error when user who is not an owner of the channel is being removed as an owner
def test_u_id_not_owner_channel_remove_owner(setup):
    post_channel_invite(setup['first_user']['token'],
                        setup['new_channel']['channel_id'],
                        setup['second_user']['auth_user_id'])
    assert post_channel_remove_owner(setup['first_user']['token'],
                                    setup['new_channel']['channel_id'],
                                    setup['second_user']['auth_user_id']).status_code == INPUTERROR

# Test that the request throws an input error when user who is the only owner of the channel is being removed as an owner
def test_u_id_only_owner_channel_remove_owner(setup):
    assert post_channel_remove_owner(setup['first_user']['token'],
                                    setup['new_channel']['channel_id'],
                                    setup['first_user']['auth_user_id']).status_code == INPUTERROR

# Test that the request throws an access error when the channel is valid but the authorised user does not have owner permissions
def test_authorised_user_is_not_owner_channel_remove_owner(setup):
    post_channel_invite(setup['first_user']['token'],
                        setup['new_channel']['channel_id'],
                        setup['second_user']['auth_user_id'])
    assert post_channel_remove_owner(setup['second_user']['token'],
                                    setup['new_channel']['channel_id'],
                                    setup['second_user']['auth_user_id']).status_code == ACCESSERROR

# Test that the request throws an access error when an invalid token is given
def test_invalid_token_channel_remove_owner(setup):
    post_channel_invite(setup['first_user']['token'],
                        setup['new_channel']['channel_id'],
                        setup['second_user']['auth_user_id'])
    assert post_channel_remove_owner(INVALID_TOKEN,
                                    setup['new_channel']['channel_id'],
                                    setup['second_user']['auth_user_id']).status_code == ACCESSERROR

# Test that the request has worked properly
def test_valid_channel_remove_owner(setup):
    post_channel_invite(setup['first_user']['token'],
                        setup['new_channel']['channel_id'],
                        setup['second_user']['auth_user_id'])
    post_channel_add_owner(setup['first_user']['token'],
                            setup['new_channel']['channel_id'],
                            setup['second_user']['auth_user_id'])
    assert post_channel_remove_owner(setup['first_user']['token'],
                                    setup['new_channel']['channel_id'],
                                    setup['second_user']['auth_user_id']) not in (INPUTERROR, ACCESSERROR)
    owners = json.loads(get_channel_details(setup['second_user']['token'],
                                            setup['new_channel']['channel_id']).text)['owner_members']
    checker = True
    for owner in owners:
        if setup['second_user']['auth_user_id'] == owner['u_id']:
            checker = False
    assert checker