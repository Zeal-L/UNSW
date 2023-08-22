'''
data_store.py

This contains a definition for a Datastore class which you should use to store your data.
You don't need to understand how it works at this point, just how to use it :)

The data_store variable is global, meaning that so long as you import it into any
python file in src, you can access its contents.

Example usage:

    from data_store import data_store

    store = data_store.get()
    print(store) # Prints { 'names': ['Nick', 'Emily', 'Hayden', 'Rob'] }

    names = store['names']

    names.remove('Rob')
    names.append('Jake')
    names.sort()

    print(store) # Prints { 'names': ['Emily', 'Hayden', 'Jake', 'Nick'] }
    data_store.set(store)
'''

## YOU SHOULD MODIFY THIS OBJECT BELOW
initial_object = {
    'users': [
        #{
            # 'u_id': -2147483648,
            # 'permission_id': -2147483648, # Global permission ID
            # 'session_ids': [-2147483648],
            # 'email': '',
            # 'name_first' : '',
            # 'name_last' : '',
            # 'password' : '',
            # 'handle_str' : '',
            # 'profile_image_url' : '',
            # 'active' : False
            # 'notifications' [
            #   {
            #       'channel_id' : 1
            #       'dm_id' : 1
            #       'notification_message: '' 
            #   }
            # ]
        #},
    ],

    'channels': [
        #{
            # 'name': '',
            # 'channel_id' : -2147483648,
            # 'is_public': False,
            # 'owner_members' : [], # We put owners in here and all_members and edit their permission_id in this array.
            # 'all_members' : [], # We put users in here and all_members and edit their permission_id in this array.
            # 'messages' : [        
            #     {
            #         'message_id' : -2147483648,
            #         'u_id' : -2147483648,
            #         'message' : "",
            #         'time_created' : -2147483648,
            #         'reacts' : [],
            #         'is_pinned' : False
            #     }
            # ]
        #},
    ],
    'dms': [
        #{
            # 'name': '',
            # 'dm_id' : -2147483648,
            # 'creator_id' : -2147483648, # refers to the user id of the person who created the dm
            # 'owner_members' : [],  # We put owners in here and all_members and edit their permission_id in this array.
            # 'all_members' : [], # We put users in here and all_members and edit their permission_id in this array.
            # 'messages' : [        
            #     {
            #         'message_id' : -2147483648,
            #         'u_id' : -2147483648,
            #         'message' : "",
            #         'time_created' : -2147483648,
            #         'reacts' : [],
            #         'is_pinned' : False
            #     }
            # ]
        #},
    ],
    'messages' : [
        #{
            # -2147483648 : ['id', 'channel/dm] # 'message_id' : ['channel_id', 'dm/channel'],
            # 'u_id' : -2147483648
        #},
    ],
    'later_messages' : [
        #{     
            #'message_id' : m_id,
            #'token' : token,
            #'channel/dm_id' : dm_id,
            #'message' : message,
            #'time_sent' : time_sent,
            #'reacts' : [],
            #'is_pinned' : False,
            #'channel/dm' : 'dm'
        #},  
    ]
}

## YOU SHOULD MODIFY THIS OBJECT ABOVE

class Datastore:
    def __init__(self):
        global initial_object
        self.__store = initial_object

    def get(self):
        return self.__store

    def set(self, store):
        if not isinstance(store, dict):
            raise TypeError('store must be of type dictionary')
        self.__store = store

print('Loading Datastore...')

global data_store
data_store = Datastore()
