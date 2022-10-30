"""
    Python 3
    coding: utf-8
    Author: Zeal Liang (z5325156)
"""

from threading import Thread

class ClientThreadManager(Thread):
    __activeUsers = []
    __blockedUsers = []
    __credentials = {}
    __maxAttempts = None
    __clientUdpInfo = {}

    def __init__(self, maxAttempts):
        Thread.__init__(self)
        with open("credentials.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                username, password = line.split()
                self.__credentials[username] = password
        self.__maxAttempts = maxAttempts

    def updateClientUdpInfo(self, username, address, port):
        self.__clientUdpInfo[username] = (address, port)

    def getClientUdpInfo(self, username):
        return self.__clientUdpInfo[username]
    
    def getMaxAttempts(self):
        return self.__maxAttempts

    def isValidUsername(self, username):
        return username in self.__credentials.keys()

    def isValidPassword(self, username, password):
        return password == self.__credentials[username]

    def addActiveUser(self, username):
        self.__activeUsers.append(username)

    def removeActiveUser(self, username):
        if username in self.__activeUsers:
            self.__activeUsers.remove(username)

    def addBlockedUser(self, username):
        self.__blockedUsers.append(username)
    
    def removeBlockedUser(self, username):
        self.__blockedUsers.remove(username)

    def getActiveUsers(self):
        return self.__activeUsers

    def getBlockedUsers(self):
        return self.__blockedUsers

    def isUserActive(self, username):
        return username in self.__activeUsers

    def isUserBlocked(self, username):
        return username in self.__blockedUsers
