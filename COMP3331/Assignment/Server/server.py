#! /usr/bin/env python3

"""
    Python 3
    Usage: python3 server.py server_port number_of_consecutive_failed_attempts
    coding: utf-8
    Author: Zeal Liang (z5325156)
"""
import os
from argparse import ArgumentParser
from socket import *
from sys import exit, stderr
from threading import Thread
from time import sleep

from clientThread import ClientThread

#######################################
#          Helper Functions           #
#######################################

def errorEXIT(message):
    print(message, file=stderr)
    exit(1)

######################################
#  Handling command line parameters  #
######################################

parser = ArgumentParser()
parser.add_argument("server_port", type=int, help="The port number of the server")
parser.add_argument("number_of_consecutive_failed_attempts", type=int, default=3, nargs='?', help="The number of consecutive failed attempts")
aargs = parser.parse_args()
if aargs.server_port < 1024 or aargs.server_port > 65535:
    errorEXIT("Error: server_port must be between 1024 and 65535")
if aargs.number_of_consecutive_failed_attempts < 1 or aargs.number_of_consecutive_failed_attempts > 5:
    errorEXIT("Error: number_of_consecutive_failed_attempts must be between 1 and 5")

serverHost = "127.0.0.1"
serverPort = aargs.server_port
serverAddress = (serverHost, serverPort)
numAttempts = aargs.number_of_consecutive_failed_attempts

######################################
#       Server starts listening      #
######################################


serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(serverAddress)

print("\n\033[34m===== Welcome to the IoT Data Network Server =====\033[0m")
print(f"\033[34m===== Server is running at port {serverPort} =====\033[0m")
print("\033[34m===== Waiting for connection request from clients... =====\033[0m")


def main():
    while True:
        serverSocket.listen()
        clientSockt, clientAddress = serverSocket.accept()
        clientThread = ClientThread(clientAddress, clientSockt, numAttempts)
        clientThread.daemon = True
        clientThread.start()

# To solve the problem that the socket's accept() method can't be  
# interrupted and cause the program to fail to exit.
# Put the socket into a daemon thread and execute it. When the main  
# thread catches the signal and exits, the program will exit with it.
while True:
    try:
        t = Thread(target=main)
        t.daemon = True
        t.start()
        sleep(9999)
    except KeyboardInterrupt:

        # Reset log files
        if os.path.exists("edge_device_log.txt"):
            with open("edge_device_log.txt", "w", encoding="utf-8") as f:
                f.truncate(0)
        if os.path.exists("upload_log.txt"):
            with open("upload_log.txt", "w", encoding="utf-8") as f:
                f.truncate(0)
        if os.path.exists("deletion_log.txt"):
            with open("deletion_log.txt", "w", encoding="utf-8") as f:
                f.truncate(0)
        print('\nreceive Ctrl-C, Bye!')
        exit(0)


