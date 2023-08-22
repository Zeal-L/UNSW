from src.data_store import data_store
from src.helper import reset_session_tracker
import os

def clear_v1():
    reset_session_tracker()
    filepath = 'photos/'
    del_list = os.listdir(filepath)
    for f in del_list:
        file_path = os.path.join(filepath, f)
        # if os.path.isfile(file_path):
        os.remove(file_path)

    store = data_store.get()
    store['users'] = [
        # {
        #     'u_id': -2147483648,
        #     'email': '',
        #     'name_first' : '',
        #     'name_last' : '',
        #     'password' : '',
        #     'profile_image_url' : '',
        #     'handle_str' : ''
        # }
    ]
    store['channels'] = [
    #    {
    #         'name': '',
    #         'channel_id' : -2147483648,
    #         'is_public': False,
    #         'owner_members' : [],
    #         'all_members' : [],
    #         'messages' : [
    #             {
    #                 'message_id' : -2147483648,
    #                 'u_id' : -2147483648,
    #                 'message' : "",
    #                 'time_created' : -2147483648
    #             }
    #         ]
    #     }
    ]
    store['dms'] = [
        # {
        #     'name': '',
        #     'dm_id' : -2147483648,
        #     'creator_id' : -2147483648, # refers to the user id of the person who created the dm
        #     'owner_members' : [],  # We put owners in here and all_members and edit their permission_id in this array.
        #     'all_members' : [], # We put users in here and all_members and edit their permission_id in this array.
        #     'messages' : [
        #         {
        #             'message_id' : -2147483648,
        #             'u_id' : -2147483648,
        #             'message' : "",
        #             'time_created' : -2147483648
        #         }
        #     ]
        # },
    ]
    store['messages'] = [
        #{
            # -2147483648 : ['id', 'channel/dm] # 'message_id' : ['channel_id', 'dm/channel']
        #},
    ]
    store['later_messages'] = [
        
    ]

    data_store.set(store)
