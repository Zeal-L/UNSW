# Imports
import json
import jwt

from src.helper import check_token, SECRET
from src.dms import user_from_token
from src.error import InputError, AccessError
from src.data_store import data_store
# Constants and Global Variables
MIN_LEN = 1
MAX_LEN = 1001
# Functions

# Implementation for search/v1
'''
Given a search query, find all messages sent by a given user in every channel/dm that they are a member of which contain that term
Arguments:
    token (string) - a JWT which when decoded refers to a potentially authorised user with a valid session
    query_str (string) - the query term that the message must be/contain
Exceptions:
    AccessError - if the given token does not refer to an authorised user with a valid session
    InputError - if the query message is not of a valid length
Return Value:
    Returns a dictionary contannig the a list of all messages which contain the search query
'''
def search_v1(token, query_str):
    check_token(token)
    data = data_store.get()
    
    if len(query_str) not in range(MIN_LEN, MAX_LEN):
        raise InputError(description='query length is invalid')
    user = data['users'][user_from_token(token)- 1]
    channels = []
    dms = []
    messages = []

    for c in data['channels']:
        members = c['owner_members'] + c['all_members']
        if user in members:
            channels.append(c)

    for d in data['dms']:
        members = d['owner_members'] + d['all_members']
        if user in members:
            dms.append(d)

    for c in channels:
        for m in c['messages']:
            if query_str in m['message']:
                messages.append(m)
    for d in dms:
        for m in d['messages']:
            if query_str in m['message']:
                messages.append(m)
    print(len(messages))           
    return {'messages' : messages}
