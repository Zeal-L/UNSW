# Imports
import json
import jwt
from src.helper import check_token, user_from_token, SECRET
from src.data_store import data_store


# Functions

# Implementation for notifications/get/v1
'''
Return a list of a given user's 20 most recent notifications, sorted in that order. Notifications include when a user is tagged,
added to a channel/dm or their message is reacted to.
Arguments:
    token (string) - a JWT which when decoded refers to a potentially authorised user with a valid session
Exceptions:
    AccessError - if the given token does not refer to an authorised user with a valid session
Return Value:
    Returns a dictionary containing the a list of the user's 20 most recent notifications
'''
def notifications_get_v1(token):
    check_token(token)
    id = user_from_token(token)
    data = data_store.get()

    notifications = data['users'][id-1]['notifications']
    # Reverse the list because of the way that notifcations are stored. The most recent ones are
    # appended to the end of the list in the data store, so we reverse the list to put them at 
    # the front. 
    notifications.reverse()
    # Return the first 20 notifications which are the 20 most recent ones for the given user.
    return {'notifications' : notifications[ : 20]}