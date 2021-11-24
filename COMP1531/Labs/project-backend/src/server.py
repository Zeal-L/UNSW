import signal
import requests
import time
from json import dumps, dump, load
from flask import Flask, request, make_response
from flask_cors import CORS
from src.error import InputError
from src import config
import src.user as user
import src.dms as dms
from src.message import message_senddm_v1
from src.other import clear_v1
from src.admin import admin_user_remove_v1, admin_userpermission_change_v1
import src.channel as channel
import src.auth as auth
import src.channels as channels
import src.message as message
from src.search import search_v1
from src.notifications import notifications_get_v1
from src.standup import standup_start_v1, standup_active_v1, standup_send_v1
from src.data_store import data_store

def quit_gracefully(*args):
    '''For coverage'''
    exit(0)

def defaultHandler(err):
    response = err.get_response()
    print('response', err, err.get_response())
    response.data = dumps({
        "code": err.code,
        "name": "System Error",
        "message": err.get_description(),
    })
    response.content_type = 'application/json'
    return response

APP = Flask(__name__)
CORS(APP)

APP.config['TRAP_HTTP_EXCEPTIONS'] = True
APP.register_error_handler(Exception, defaultHandler)

#### NO NEED TO MODIFY ABOVE THIS POINT, EXCEPT IMPORTS

# Example
@APP.route("/echo", methods=['GET'])
def echo():
    data = request.args.get('data')

    if data == 'echo':
        raise InputError(description='Cannot echo "echo"')
    return dumps({
        'data': data
    })

# The following decorator ensures that the data store is always loaded on server start.
@APP.before_first_request
def load_file():
    with open('./database.json', 'r') as FILE:
        data_store.set(load(FILE))

# The following decorator ensures that after each request, the data store is saved.
@APP.after_request
def save(resp):
    store = data_store.get()
    with open('./database.json', 'w') as FILE:
        dump(store, FILE)
    return resp

@APP.after_request
def check_sendlater(response):
    data = data_store.get()
    messages = data['later_messages']
    #print(f'there are {len(messages)} messages waiting to be sent')
    current_time = int(time.time())
    for mes in messages:
        if mes['time_sent'] <= current_time:
            if mes['channel/dm'] == 'channel':
                token = mes['token']
                id = mes['channel/dm_id']
                text = mes['message']
                message.message_send_v1(token, id, text)
                data['later_messages'].remove(mes)
                #print('sent message')
            elif mes['channel/dm'] == 'dm':
                token = mes['token']
                id = mes['channel/dm_id']
                text = mes['message']
                message.message_senddm_v1(token, id, text)
                data['later_messages'].remove(mes)

    return response

@APP.route("/auth/login/v2", methods=['POST'])
def login():
    data = request.get_json()
    resp = auth.auth_login_v2(data['email'], data['password'])

    return dumps({
        'token' : resp['token'],
        'auth_user_id' : resp['auth_user_id']
    })

@APP.route("/auth/register/v2", methods=['POST'])
def register():
    data = request.get_json()
    resp = auth.auth_register_v2(data['email'], data['password'], data['name_first'], data['name_last'])

    return dumps({
        'token' : resp['token'],
        'auth_user_id' : resp['auth_user_id']
    })

@APP.route("/auth/logout/v1", methods=['POST'])
def logout():
    data = request.get_json()
    auth.auth_logout_v1(data['token'])
    return dumps({})

@APP.route("/auth/passwordreset/request/v1", methods=['POST'])
def passwordreset_request():
    data = request.get_json()
    auth.auth_password_request_v1(data['email'])
    return dumps({})

@APP.route("/auth/passwordreset/reset/v1", methods=['POST'])
def passwordreset_reset():
    data = request.get_json()
    auth.auth_password_reset_v1(data['reset_code'],data['new_password'])
    return dumps({})

# Flask routes for channels/* features
@APP.route('/channels/create/v2', methods=["POST"])
def channels_create():
    data = request.get_json()
    c_id = channels.channels_create_v2(data['token'], data['name'], data['is_public'])
    return dumps(c_id)

@APP.route('/channels/listall/v2', methods=['GET'])
def channels_listall():
    token = request.args.get('token')
    resp = channels.channels_listall_v2(token)
    return dumps(resp)

@APP.route('/channels/list/v2', methods=["GET"])
def channels_list():
    token = request.args.get('token')
    resp = channels.channels_list_v2(token)
    return dumps(resp)

@APP.route("/users/all/v1", methods=['GET'])
def users_all():
    token = request.args.get('token')
    resp = user.users_all_v1(token)
    return dumps(resp)

@APP.route("/user/profile/v1", methods=['GET'])
def user_profile():
    token = request.args.get('token')
    u_id = int(request.args.get('u_id'))
    resp = user.user_profile_v1(token, u_id)
    return dumps({
        'user' : resp
    })

@APP.route("/user/profile/setname/v1", methods=['PUT'])
def user_profile_setname():
    data = request.get_json()
    user.user_profile_setname_v1(data['token'], data['name_first'], data['name_last'])
    return dumps({})

@APP.route("/user/profile/setemail/v1", methods=['PUT'])
def user_profile_setemail():
    data = request.get_json()
    user.user_profile_setemail_v1(data['token'], data['email'])
    return dumps({})

@APP.route("/user/profile/sethandle/v1", methods=['PUT'])
def user_profile_sethandle():
    data = request.get_json()
    user.user_profile_sethandle_v1(data['token'], data['handle_str'])
    return dumps({})

# Flask routes for dm/* features
@APP.route("/dm/create/v1", methods = ['POST'])
def dm_create():
    data = request.get_json() # data = {'token' : token, 'u_ids': [1,2,3]}
    dm = dms.dm_create_v1(data['token'], data['u_ids'])
    return dumps(dm)

@APP.route("/dm/details/v1", methods=["GET"])
def dm_details():
    token = request.args.get('token')
    id = int(request.args.get('dm_id'))
    details = dms.dm_details_v1(token, id)
    return dumps(details)

@APP.route('/dm/list/v1', methods=['GET'])
def list_dms():
    token = request.args.get('token')
    resp = dms.dm_list_v1(token)
    return dumps(resp)

@APP.route("/dm/remove/v1", methods=['DELETE'])
def dm_remove():
    data = request.get_json()
    remove = dms.dm_remove_v1(data['token'], data['dm_id'])
    return dumps(remove)

@APP.route("/dm/leave/v1", methods=['POST'])
def dm_leave():
    data = request.get_json()
    leave = dms.dm_leave_v1(data['token'], data['dm_id'])
    return dumps(leave)

@APP.route("/dm/messages/v1", methods=['GET'])
def dm_messages():
    token = request.args.get('token')
    id = int(request.args.get('dm_id'))
    start = int(request.args.get('start'))
    messages = dms.dm_messages_v1(token, id, start)
    return dumps(messages)

# Flask routes for message/* features
@APP.route("/message/senddm/v1", methods=['POST'])
def send_dm():
    data = request.get_json()
    message_id = message.message_senddm_v1(data['token'], data['dm_id'], data['message'])
    return dumps(message_id)

@APP.route('/message/sendlaterdm/v1', methods=['POST'])
def sendlater_dm():
    data = request.get_json()
    message_id = message.message_sendlaterdm_v1(data['token'], data['dm_id'], data['message'], data['time_sent'])
    return dumps(message_id)

@APP.route("/clear/v1", methods=['DELETE'])
def clear():
    clear_v1()
    return dumps({})

@APP.route("/message/send/v1", methods=['POST'])
def message_send():
    data = request.get_json()
    ret = message.message_send_v1(data['token'], data['channel_id'], data['message'])
    return dumps(ret)

@APP.route('/message/sendlater/v1', methods=['POST'])
def message_sendlater():
    data = request.get_json()
    message_id = message.message_sendlater_v1(data['token'], data['channel_id'], data['message'], data['time_sent'])
    return dumps(message_id)

@APP.route("/message/edit/v1", methods=['PUT'])
def message_edit():
    data = request.get_json()
    ret = message.message_edit_v1(data['token'], data['message_id'], data['message'])
    return dumps(ret)

@APP.route("/message/remove/v1", methods=['DELETE'])
def message_remove():
    data = request.get_json()
    ret = message.message_remove_v1(data['token'], data['message_id'])
    return dumps(ret)

@APP.route('/message/share/v1', methods=['POST'])
def message_share():
    data = request.get_json()
    share = message.message_share_v1(data['token'], data['og_message_id'], data['message'], data['channel_id'], data['dm_id'])
    return dumps(share)

@APP.route("/message/react/v1", methods=['POST'])
def message_react():
    data = request.get_json()
    ret = message.message_react_v1(data['token'], data['message_id'], data['react_id'])
    return dumps(ret)

@APP.route("/message/unreact/v1", methods=['POST'])
def message_unreact():
    data = request.get_json()
    ret = message.message_unreact_v1(data['token'], data['message_id'], data['react_id'])
    return dumps(ret)

@APP.route("/message/pin/v1", methods=['POST'])
def message_pin():
    data = request.get_json()
    ret = message.message_pin_v1(data['token'], data['message_id'])
    return dumps(ret)

@APP.route("/message/unpin/v1", methods=['POST'])
def message_unpin():
    data = request.get_json()
    ret = message.message_unpin_v1(data['token'], data['message_id'])
    return dumps(ret)

@APP.route("/channel/invite/v2", methods=['POST'])
def channel_invite():
    data = request.get_json()
    resp = channel.channel_invite_v2(data['token'], data['channel_id'], data['u_id'])
    return dumps(resp)

@APP.route("/channel/details/v2", methods=['GET'])
def channel_details():
    token = request.args.get('token')
    channel_id = int(request.args.get('channel_id'))
    resp = channel.channel_details_v2(token, channel_id)
    return dumps(resp)

@APP.route("/channel/messages/v2", methods=['GET'])
def channel_messages():
    token = request.args.get('token')
    channel_id = int(request.args.get('channel_id'))
    start = int(request.args.get('start'))
    resp = channel.channel_messages_v2(token, channel_id, start)
    return dumps(resp)

@APP.route("/channel/join/v2", methods=['POST'])
def channel_join():
    data = request.get_json()
    resp = channel.channel_join_v2(data['token'], data['channel_id'])
    return dumps(resp)

@APP.route("/channel/leave/v1", methods=['POST'])
def channel_leave():
    data = request.get_json()
    resp = channel.channel_leave_v1(data['token'], data['channel_id'])
    return dumps(resp)

@APP.route("/channel/addowner/v1", methods=['POST'])
def channel_add_owner():
    data = request.get_json()
    resp = channel.channel_add_owner_v1(data['token'], data['channel_id'], data['u_id'])
    return dumps(resp)

@APP.route("/channel/removeowner/v1", methods=['POST'])
def channel_remove_owner():
    data = request.get_json()
    channel.channel_remove_owner_v1(data['token'], data['channel_id'], data['u_id'])
    return dumps({})

@APP.route("/admin/user/remove/v1", methods=['DELETE'])
def remove():
    data = request.get_json()
    admin_user_remove_v1(data['token'], data['u_id'])
    return dumps({})

@APP.route("/admin/userpermission/change/v1", methods=['POST'])
def change():
    data = request.get_json()
    admin_userpermission_change_v1(data['token'], data['u_id'], data['permission_id'])
    return dumps({})

@APP.route("/standup/start/v1", methods=['POST'])
def start():
    data = request.get_json()
    resp = standup_start_v1(data['token'], data['channel_id'], data['length'])
    return dumps(resp)

@APP.route("/standup/active/v1", methods=['GET'])
def active():
    token = request.args.get('token')
    channel_id = int(request.args.get('channel_id'))
    resp = standup_active_v1(token, channel_id)
    return dumps(resp)

@APP.route("/standup/send/v1", methods=['POST'])
def send():
    data = request.get_json()
    standup_send_v1(data['token'], data['channel_id'], data['message'])
    return dumps({})

# Flask routing for search/v1
@APP.route('/search/v1', methods=['GET'])
def search():
    token = request.args.get('token')
    query_str = request.args.get('query_str')
    search_results = search_v1(token, query_str)
    return dumps(search_results)

# Flask route for notifications
@APP.route('/notifications/get/v1', methods=['GET'])
def get_notifications():
    token = request.args.get('token')
    notifications = notifications_get_v1(token)
    return dumps(notifications)
    
@APP.route("/static/<img_url>")
def profile_img_url(img_url):
    image_data = open('photos/' + img_url, "rb").read()
    response = make_response(image_data)
    response.headers['Content-Type'] = 'image/jpg'
    return response
    
@APP.route("/user/stats/v1", methods=['GET'])
def user_stats():
    token = request.args.get('token')
    resp = user.user_stats_v1(token)
    return dumps(resp)

@APP.route("/users/stats/v1", methods=['GET'])
def users_stats():
    token = request.args.get('token')
    resp = user.users_stats_v1(token)
    return dumps(resp)

@APP.route("/user/profile/uploadphoto/v1", methods=['POST'])
def user_profile_uploadphoto():
    data = request.get_json()

    user.user_profile_uploadphoto_v1(data['token'], data['img_url'],
                                    data['x_start'], data['y_start'],
                                    data['x_end'], data['y_end'])
    return dumps({})

#### NO NEED TO MODIFY BELOW THIS POINT

if __name__ == "__main__":
    signal.signal(signal.SIGINT, quit_gracefully) # For coverage
    APP.run(port=config.port) # Do not edit this port
