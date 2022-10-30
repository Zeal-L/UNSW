#! /usr/bin/env python3

"""
    Python 3
    Usage: python3 client.py server_IP server_port client_udp_server_port
    coding: utf-8
    Author: Zeal Liang (z5325156)
"""
import json
import os
import struct
from argparse import ArgumentParser
from re import match
from socket import *
from sys import exit, stderr
from threading import Thread
from time import sleep
from tqdm import tqdm


checkUDPActive = False
checkOUT = False

#######################################
#          Helper Functions           #
#######################################

def helpINFO():
    print("EDG - Edge data generation\n\tEDG [fileID] [dataAmount]\n\tClient randomly generates integer data samples\n\tSamples are saved in a text file")
    print("UED - Upload edge data\n\tUED [fileID]\n\tClient transfers data file to server\n\tServer appends upload log")
    print("SCS - Server computation service\n\tSCS [fileID] [computationOperation]\n\tServer performs some computation on previously uploaded data\n\tComputations include [SUM, AVERAGE, MAX, MIN]")
    print("DTE - Delete data file\n\tDTE [fileID]\n\tServer deletes its copy of the data file\n\tAppends deletion log")
    print("AED - Active edge devices\n\tAED\n\tList all active devices (except device issuing command)\n\tRead the log file and send relevant information to client")
    print("OUT - Exit edge network\n\tOUT\n\tDevice leaves the network, client quits\n\tServer updates state/log about active devices")
    print("UVF - Upload video file\n\tUVF [deviceName] [filename]\n\tFile is transferred directly between clients using UDP\n")

def myPrint(colour, msg):
    flag = '38m'
    if colour == "red":
        flag = '31m'
    elif colour == "green":
        flag = '32m'
    elif colour == "yellow":
        flag = '33m'
    elif colour == "blue":
        flag = '34m'
    print(f"\033[{flag}{msg}\033[0m")

def errorEXIT(message):
    print(f"\033[31m{message}\033[0m", file=stderr)
    exit(1)

def recieveSocket():
    global clientSocket
    headerSize = struct.unpack('i', clientSocket.recv(4))[0]
    data = clientSocket.recv(headerSize)
    return json.loads(data.decode())
    
def sendSocket(header):
    global clientSocket
    payload = json.dumps(header).encode()
    clientSocket.sendall(struct.pack('i', len(payload)))
    clientSocket.sendall(payload)


######################################
#  Handling command line parameters  #
######################################

parser = ArgumentParser()
parser.add_argument("server_IP", type=str, help="IP address of machine on which server is running")
parser.add_argument("server_port", type=int, help="should match the first argument for the server")
parser.add_argument("client_udp_server_port", type=int, help="where client will receive data from other clients")
aargs = parser.parse_args()
if match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", aargs.server_IP) is None:
    errorEXIT("Error: server_IP is not a valid IP address")
if aargs.server_port < 1024 or aargs.server_port > 65535:
    errorEXIT("Error: server_port must be between 1024 and 65535")
if aargs.client_udp_server_port < 1024 or aargs.client_udp_server_port > 65535:
    errorEXIT("Error: client_udp_server_port must be between 1024 and 65535")

serverHost = aargs.server_IP
serverPort = aargs.server_port
serverAddress = (serverHost, serverPort)
clientHost = "127.0.0.1"
clientUdpPort = aargs.client_udp_server_port
clientAddress = (clientHost, clientUdpPort)

#######################################
#    Start connecting to the server   #
#######################################

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect(serverAddress)

myPrint("blue", "\n===== Welcome to the IoT Data Network Client =====\n")
print("Please enter your username and password to login")


##########################################
#  Login user information authentication #
##########################################

while True:
    try:
        username = input("Username: ").strip()
        password = input("Password: ").strip()

    except KeyboardInterrupt:
        clientSocket.close()
        print('\nreceive Ctrl-C, Bye!')
        exit(0)
    

    sendSocket({
        "command": "login",
        "username": username,
        "password": password
    })
    
    res = recieveSocket()
    if res['command'] != 'loginResponse':
        clientSocket.close()
        errorEXIT("Error: Invalid loginResponse from server\n")
    
    if res['response'] == "0":
        myPrint("red", "Username does not exist. Please try again\n")
        continue
    
    elif res['response'] == "-1":
        myPrint("red", "Invalid Password. Please try again\n")
        continue
    
    elif res['response'] == "-2":
        clientSocket.close()
        errorEXIT("Invalid Password. Your account has been blocked. Please try again later\n")
    
    elif res['response'] == "-3":
        myPrint("red", "This user is already logged in. Please try again\n")
        continue
    
    elif res['response'] == "-4":
        myPrint("red", "Your account is blocked due to multiple authentication failures. Please try again later\n")
        continue
    
    elif res['response'] == "1":
        myPrint("green", f"Login successful. Welcome {username}!\n")
        sendSocket({
            "command": "clientUdpPort",
            "clientUdpPort": clientUdpPort
        })
        break


#####################################
#   UdpServer for P2P connections   #
#####################################

def clientUdpServer(clientUdpSocket:socket):
    global checkUDPActive
    while True:
        
        # receive headerSize
        receiveData = clientUdpSocket.recv(4)
        headerSize = struct.unpack('i', receiveData)[0]
        
        # receive header
        receiveData = clientUdpSocket.recv(headerSize)
        res = json.loads(receiveData.decode())
        
        myPrint("yellow", f"\nReceiving File {res['fileName']} from {res['deviceName']}...\n")
        checkUDPActive = True
        # receive data
        with open(f"{res['deviceName']}_{res['fileName']}", 'wb') as f:
            # bar = tqdm(total=res['fileSize'], ascii=True, unit='B', unit_scale=True)
            offset = 0
            dataBuffer = []
            while offset < res['fileSize']:
                data = clientUdpSocket.recv(1024)
                offset += len(data)
                dataBuffer.append(data)
            #     bar.update(len(data))
            # bar.clear()
            # bar.close()
            for data in dataBuffer:
                f.write(data)
        
        myPrint("green", f"\nDownload completed. File {res['deviceName']}_{res['fileName']} is saved in the current directory.\n")
        if not checkOUT:
            print("--------------------------------------------------")
            print("Enter one of the following commands (EDG, UED, SCS, DTE, AED, OUT, UVF) or help:")
        checkUDPActive = False


def UVF_Upload(inputText, res):
    global checkUDPActive
    checkUDPActive = True
    myPrint("yellow", f"\nDevice {inputText[1]} is online, beginning to upload file {inputText[2]}...\n")
    targetAddress = (res['clientUdpHost'], int(res['clientUdpPort']))

    fileSize = os.path.getsize(inputText[2])
    header = {
        "fileName": inputText[2],
        "fileSize": fileSize,
        "deviceName": username
    }
    
    payload = json.dumps(header).encode()
    
    clientUdpSocket.sendto(struct.pack('i', len(payload)), targetAddress)
    clientUdpSocket.sendto(payload, targetAddress)
    
    with open(f"{inputText[2]}", "rb") as f:
        # bar = tqdm(total=fileSize, ascii=True, unit='B', unit_scale=True)
        offset = 0
        while offset < fileSize:
            data = f.read(1024)
            clientUdpSocket.sendto(data, targetAddress)
            offset += len(data)
        #     bar.update(len(data))
        # bar.clear()
        # bar.close()

    myPrint("green", f"\nUpload completed. {inputText[2]} has been sent to {inputText[1]}\n")
    if not checkOUT:
        print("--------------------------------------------------")
        print("Enter one of the following commands (EDG, UED, SCS, DTE, AED, OUT, UVF) or help:")
    checkUDPActive = False


clientUdpSocket = socket(AF_INET, SOCK_DGRAM)
clientUdpSocket.bind(clientAddress)
# Set the UDP receive buffer to 1Gb
clientUdpSocket.setsockopt(SOL_SOCKET, SO_RCVBUF, 1024*1024*1024)


try:
    UdpServerThread = Thread(target=clientUdpServer, args=(clientUdpSocket,))
    UdpServerThread.daemon = True
    UdpServerThread.start()

except KeyboardInterrupt:
    while checkUDPActive:
        sleep(0.1)
    clientUdpSocket.close()
    clientSocket.close()
    print('\nreceive Ctrl-C, Bye!')
    exit(0)

#####################################
#   Parsing user commands section   #
#####################################

while True:
    print("--------------------------------------------------")
    print("Enter one of the following commands (EDG, UED, SCS, DTE, AED, OUT, UVF) or help:")
    try:
        inputText = input().strip().split()
    except KeyboardInterrupt:
        while checkUDPActive:
            sleep(0.1)
        clientSocket.close()
        print('\nreceive Ctrl-C, Bye!')
        exit(0)
        
    if inputText == []:
        continue
    
    ######  help  ######
    elif inputText[0] == 'help':
        if len(inputText) != 1:
            myPrint("red", "Error: invalid number of arguments\n\thelp\n")
            continue
        helpINFO()
    
    ######  EDG  ######
    elif inputText[0] == 'EDG':
        if len(inputText) != 3:
            myPrint("red", "Error: invalid number of arguments\n\tEDG [fileID] [dataAmount]\n")
            continue
        elif not inputText[1].isdigit():
            myPrint("red", "Error: fileID must be integer\n\tEDG [fileID] [dataAmount]\n")
            continue
        elif not inputText[2].isdigit():
            myPrint("red", "Error: dataAmount must be an integer\n\tEDG [fileID] [dataAmount]\n")
            continue
        elif int(inputText[2]) <= 0:
            myPrint("red", "Error: dataAmount must be a positive integer\n\tEDG [fileID] [dataAmount]\n")
            continue
        
        myPrint("yellow", f"\nThe edge device is generating {inputText[2]} data samples…\n")
        with open(f"{username}-{inputText[1]}.txt", 'w+', encoding='utf-8') as f:
            bar = tqdm(total=int(inputText[2]))
            for i in range(int(inputText[2])):
                f.write(f"{i+1}\n")
                bar.update(1)
            bar.clear()
            bar.close()
        myPrint("green", f"\nData generation completed. File {username}-{inputText[1]}.txt is saved in the current directory.\n")

    ######  UED  ######
    elif inputText[0] == 'UED':
        if len(inputText) != 2:
            myPrint("red", "Error: invalid number of arguments\n\tUED [fileID]\n")
            continue
    
        if not inputText[1].isdigit():
            myPrint("red", "Error: fileID must be integer\n\tUED [fileID]\n")
            continue
        
        if os.path.exists(f"{username}-{inputText[1]}.txt"):
            with open(f"{username}-{inputText[1]}.txt", "r", encoding="utf-8") as f:
                count = len(f.readlines())
        else:
            myPrint("red", "Error: the file to be uploaded does not exis\n")
            continue
        
        sendSocket({
            "command": "UED",
            "fileID": inputText[1],
            "dataAmount": count,
            "fileSize": os.path.getsize(f"{username}-{inputText[1]}.txt")
        })
        
        myPrint("yellow", "Beginning to upload data file…\n")
        with open(f"{username}-{inputText[1]}.txt", "rb") as f:
            bar = tqdm(total=count)
            for line in f:
                clientSocket.sendall(line)
                bar.update(1)
            bar.clear()
            bar.close()

        res = recieveSocket()
        if res['command'] == "UEDResponse":
            myPrint("green", "The server replies that the data file has been successfully received!")

    ######  SCS  ######
    elif inputText[0] == 'SCS':
        if len(inputText) != 3:
            myPrint("red", "Error: invalid number of arguments\n\tSCS [fileID] [SUM, AVERAGE, MAX, MIN]\n")
            continue
        if not inputText[1].isdigit():
            myPrint("red", "Error: fileID must be integer\n\tSCS [fileID] [SUM, AVERAGE, MAX, MIN]\n")
            continue
        if inputText[2] not in ["SUM", "AVERAGE", "MAX", "MIN"]:
            myPrint("red", "Error: invalid computationOperation! Must be any one of the following\n\t [SUM, AVERAGE, MAX, MIN]\n")
            continue
        
        sendSocket({
            "command": "SCS",
            "fileID": inputText[1],
            "computationOperation": inputText[2],
        })
        
        res = recieveSocket()
        if res['command'] == "SCSResponse":
            if res['response'] == "0":
                myPrint("red", "Error: The file does not exist at the server side\n")
            elif res['response'] == "1":
                myPrint("green", f"Receive the calculation results back from the server:\nResult:\t{res['result']}\n")
        else:
            myPrint("red", "Error: Invalid SCSResponse from server\n")
    
    ######  DTE  ######
    elif inputText[0] == 'DTE':
        if len(inputText) != 2:
            myPrint("red", "Error: invalid number of arguments\n\tDTE [fileID]\n")
            continue
        
        if not inputText[1].isdigit():
            myPrint("red", "Error: fileID must be integer\n\tUED [fileID]\n")
            continue
        
        sendSocket({
            "command": "DTE",
            "fileID": inputText[1]
        })
        res = recieveSocket()
        
        if res['command'] == "DTEResponse":
            if res['response'] == "0":
                myPrint("red", "Error: The file does not exist at the server side\n")
            elif res['response'] == "1":
                myPrint("green", f"The file with ID of {inputText[1]} has been successfully removed from the central server\n")
        else:
            myPrint("Error: Invalid DTEResponse from server\n")
    
    ######  AED  ######
    elif inputText[0] == 'AED':
        if len(inputText) != 1:
            myPrint("red", "Error: AED command does not take any arguments\n")
            continue
        
        sendSocket({
            "command": "AED"
        })

        while True:
            res = recieveSocket()
            if res['command'] == 'respondAED':
                print()
                for line in res['respond']:
                    print(line)
                break
    
    ######  OUT  ######
    elif inputText[0] == 'OUT':
        if len(inputText) != 1:
            myPrint("red", "Error: OUT command does not take any arguments\n")
            continue
        sendSocket({
            "command": "logout"
        })
        checkOUT = True
        while checkUDPActive:
            sleep(0.1)
        myPrint("green", f"Goodbye {username}!\n")
        break
    
    ######  UVF  ######
    elif inputText[0] == 'UVF':
        if len(inputText) != 3:
            myPrint("red", "Error: invalid number of arguments\n\tUVF [deviceName] [filename]\n")
            continue
        
        if not os.path.exists(inputText[2]):
            myPrint("red", f"Error: The file {inputText[2]} does not exist\n")
            continue
        
        if inputText[1] == username:
            myPrint("red", f"Error: You can't send the file to yourself.\n")
            continue
        
        sendSocket({
            "command": "UVF",
            "deviceName": inputText[1],
        })
        res = recieveSocket()
        
        if res['command'] == 'UVFResponse':
            if res['response'] == '0':
                myPrint("red", f"\nDevice {inputText[1]} is currently offline, please try again later.")
            
            elif res['response'] == '1':
                try:
                    t = Thread(target=UVF_Upload, args=(inputText, res,))
                    t.daemon = True
                    t.start()
                except KeyboardInterrupt:
                    while checkUDPActive:
                        sleep(0.1)
                    clientUdpSocket.close()
                    clientSocket.close()
                    print('\nreceive Ctrl-C, Bye!')
                    exit(0)
            elif res['response'] == '2':
                myPrint("red", f"\nDevice {inputText[1]} is not in server's database, please try it again.")
                    
        else:
            myPrint("Error: Invalid UVFResponse from server\n")

    else:
        myPrint("red", "Invalid command! Please enter help if you need an example.")

while checkUDPActive:
    sleep(0.1)


# close the socket
clientSocket.close()