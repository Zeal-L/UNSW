import requests
from src import config


##################################################
# Frequently used constants
##################################################

INPUTERROR = 400
ACCESSERROR = 403


##################################################
# Helper Function
##################################################

def post_login(email, password):
    resp = requests.post(config.url + 'auth/login/v2', json={
        'email' : email,
        'password' : password
    })
    return resp

def post_register(email, password, name_first, name_last):
    resp = requests.post(config.url + 'auth/register/v2', json={
            'email' : email,
            'password' : password,
            'name_first' : name_first,
            'name_last' : name_last
    })
    return resp

def post_logout(token):
    resp = requests.post(config.url + 'auth/logout/v1', json={
        'token' : token
    })
    return resp

def post_channels_create(token, name, is_public):
    resp = requests.post(config.url + 'channels/create/v2', json={
        'token' : token,
        'name' : name,
        'is_public' : is_public
    })
    return resp

def get_channel_details(token, channel_id):
    resp = requests.get(config.url + 'channel/details/v2', params = {
        'token' : token,
        'channel_id' : channel_id,
    })
    return resp

def post_channel_invite(token, channel_id, u_id):
    resp = requests.post(config.url + 'channel/invite/v2', json={
        'token' : token,
        'channel_id' : channel_id,
        'u_id' : u_id
    })
    return resp

def post_channel_join(token, channel_id):
    resp = requests.post(config.url + 'channel/join/v2', json = {
        'token' : token,
        'channel_id' : channel_id
    })
    return resp

def post_channel_leave(token, channel_id):
    resp = requests.post(config.url + 'channel/leave/v1', json = {
        'token' : token,
        'channel_id' : channel_id
    })
    return resp

def post_channel_add_owner(token, channel_id, u_id):
    resp = requests.post(config.url + 'channel/addowner/v1', json = {
        'token' : token,
        'channel_id' : channel_id,
        'u_id' : u_id
    })
    return resp

def post_channel_remove_owner(token, channel_id, u_id):
    resp = requests.post(config.url + 'channel/removeowner/v1', json = {
        'token' : token,
        'channel_id' : channel_id,
        'u_id' : u_id
    })
    return resp

def get_channel_messages(token, channel_id, start):
    resp = requests.get(config.url + 'channel/messages/v2', params = {
        'token' : token,
        'channel_id' : channel_id,
        'start' : start
    })
    return resp

def post_message_send(token, channel_id, message):
    resp = requests.post(config.url + 'message/send/v1', json={
        'token' : token,
        'channel_id' : channel_id,
        'message' : message
    })
    return resp

def get_users_all(token):
    resp = requests.get(config.url + 'users/all/v1', params = {
        'token' : token
    })
    return resp

def get_user_profile(token, u_id):
    resp = requests.get(config.url + 'user/profile/v1', params = {
        'token' : token,
        'u_id' : u_id
    })
    return resp

def put_user_profile_setname(token, name_first, name_last):
    resp = requests.put(config.url + 'user/profile/setname/v1', json = {
        'token' : token,
        'name_first' : name_first,
        'name_last' : name_last
    })
    return resp

def put_user_profile_setemail(token, email):
    resp = requests.put(config.url + 'user/profile/setemail/v1', json = {
        'token' : token,
        'email' : email
    })
    return resp

def put_user_profile_sethandle(token, handle_str):
    resp = requests.put(config.url + 'user/profile/sethandle/v1', json = {
        'token' : token,
        'handle_str' : handle_str
    })
    return resp

def post_dm_create(token, u_ids):
    resp = requests.post(config.url + 'dm/create/v1', json={
        'token' : token,
        'u_ids' : u_ids
    })
    return resp

def get_dm_details(token, dm_id):
    resp = requests.get(config.url + 'dm/details/v1', params={
        'token' : token,
        'dm_id' : dm_id
    })
    return resp

def get_dm_messages(token, dm_id, start):
    resp = requests.get(config.url + 'dm/messages/v1', params={
        'token' : token,
        'dm_id' : dm_id,
        'start' : start
    })
    return resp

def post_message_senddm(token, dm_id, message):
    resp = requests.post(config.url + 'message/senddm/v1', json={
        'token' : token,
        'dm_id' : dm_id,
        'message' : message
    })
    return resp

def post_channel_add_owner_v1(token, channel_id, u_id):
    resp = requests.post(config.url + 'channel/addowner/v1', json = {
        'token' : token,
        'channel_id' : channel_id,
        'u_id' : u_id
    })
    return resp

def put_message_edit_v1(token, message_id, message):
    resp = requests.put(config.url + 'message/edit/v1', json = {
        'token' : token,
        'message_id' : message_id,
        'message' : message
    })
    return resp

def delete_message_remove_v1(token, message_id):
    resp = requests.delete(config.url + 'message/remove/v1', json = {
        'token' : token,
        'message_id' : message_id,
    })
    return resp

def delete_admin_user_remove(token, u_id):
    resp = requests.delete(config.url + 'admin/user/remove/v1', json={
        'token' : token,
        'u_id' : u_id
    })
    return resp

def post_admin_userpermission_change(token, u_id, permission_id):
    resp = requests.post(config.url + 'admin/userpermission/change/v1', json={
        'token' : token,
        'u_id' : u_id,
        'permission_id' : permission_id
    })
    return resp

def post_standup_start(token, channel_id, length):
    resp = requests.post(config.url + 'standup/start/v1', json={
        'token' : token,
        'channel_id' : channel_id,
        'length' : length
    })
    return resp

def get_standup_active(token, channel_id):
    resp = requests.get(config.url + 'standup/active/v1', params={
        'token' : token,
        'channel_id' : channel_id
    })
    return resp

def post_standup_send(token, channel_id, message):
    resp = requests.post(config.url + 'standup/send/v1', json={
        'token' : token,
        'channel_id' : channel_id,
        'message' : message
    })
    return resp

def post_message_react_v1(token, message_id, react_id):
    resp = requests.post(config.url + 'message/react/v1', json={
        'token' : token,
        'message_id' : message_id,
        'react_id' : react_id
    })
    return resp

def post_message_unreact_v1(token, message_id, react_id):
    resp = requests.post(config.url + 'message/unreact/v1', json={
        'token' : token,
        'message_id' : message_id,
        'react_id' : react_id
    })
    return resp

def post_message_pin_v1(token, message_id):
    resp = requests.post(config.url + 'message/pin/v1', json={
        'token' : token,
        'message_id' : message_id,
    })
    return resp

def post_message_unpin_v1(token, message_id):
    resp = requests.post(config.url + 'message/unpin/v1', json={
        'token' : token,
        'message_id' : message_id,
    })
    return resp

def post_user_profile_uploadphoto(token, img_url, x_start, y_start, x_end, y_end):
    resp = requests.post(config.url + 'user/profile/uploadphoto/v1', json={
        'token' : token,
        'img_url' : img_url,
        'x_start' : x_start,
        'y_start' : y_start,
        'x_end' : x_end,
        'y_end' : y_end,
        })
    return resp

# def post_standup_start(token, channel_id, length):
#     resp = requests.post(config.url + 'standup/start/v1', json={
#         'token' : token,
#         'channel_id' : channel_id,
#         'length' : length
#     })
#     return resp

# def get_standup_active(token, channel_id):
#     resp = requests.get(config.url + 'standup/active/v1', params={
#         'token' : token,
#         'channel_id' : channel_id
#     })
#     return resp

# def post_standup_send(token, channel_id, message):
#     resp = requests.post(config.url + 'standup/send/v1', json={
#         'token' : token,
#         'channel_id' : channel_id,
#         'message' : message
#     })
#     return resp

def post_auth_passwordreset_request(email):
    resp = requests.post(config.url + 'auth/passwordreset/request/v1', json={
        'email' : email
    })
    return resp

def post_auth_passwordreset_reset(reset_code, new_password):
    resp = requests.post(config.url + 'auth/passwordreset/reset/v1', json={
        'reset_code' : reset_code,
        'new_password' : new_password
    })
    return resp