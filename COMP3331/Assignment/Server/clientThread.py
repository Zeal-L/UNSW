"""
    Python 3
    coding: utf-8
    Author: Zeal Liang (z5325156)
"""

from datetime import datetime
import threading
from clientThreadManager import ClientThreadManager
import json, os, struct
from tqdm import tqdm

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

class ClientThread(ClientThreadManager):
    lock = threading.Lock() 
    def __init__(self, clientAddress, clientSocket, maxAttempts):
        ClientThreadManager.__init__(self, maxAttempts)
        self.username = None
        self.clientAddress = clientAddress
        self.clientSocket = clientSocket
        self.clientAlive = False
        self.numAttempts = 0
        myPrint(None, f"\n===== New connection created for: {self.clientAddress[0]}:{self.clientAddress[1]} =====")
        self.clientAlive = True
        
    def recieveSocket(self):
        headerSize = struct.unpack('i', self.clientSocket.recv(4))[0]
        data = self.clientSocket.recv(headerSize)
        return json.loads(data.decode())
    
    def sendSocket(self, header):
        payload = json.dumps(header).encode()
        self.clientSocket.sendall(struct.pack('i', len(payload)))
        self.clientSocket.sendall(payload)
        
    def getDataAmount(self, fileID):
        self.lock.acquire()
        with open("upload_log.txt", "r", encoding="utf-8") as f:
            for line in f:
                if line.split(';')[0].strip() == self.username and line.split(';')[2].strip() == fileID:
                    self.lock.release()
                    return line.split(';')[3].strip()
        self.lock.release()
        return None
    
    def run(self):
        while self.clientAlive:
            try:
                data = self.clientSocket.recv(4)
            except ConnectionResetError as e:
                self.clientAlive = False
                super().removeActiveUser(self.username)
                self.removeEdgeDeviceLog()
                myPrint("red", e)
                myPrint(None, f"===== User {self.username} disconnected from {self.clientAddress[0]}:{self.clientAddress[1]} =====")
                self.clientSocket.close()
                break
            
            # if the message from client is empty, the client would be 
            # off-line then set the client as offline (alive=Flase)
            if data.decode() == '':
                self.clientAlive = False
                super().removeActiveUser(self.username)
                self.removeEdgeDeviceLog()
                myPrint(None, f"===== User {self.username} disconnected from {self.clientAddress[0]}:{self.clientAddress[1]} =====")
                self.clientSocket.close()
                break
            headerSize = struct.unpack('i', data)[0]
            data = self.clientSocket.recv(headerSize)
            res = json.loads(data.decode())
            
            ###### login ######
            if res['command'] == 'login':
                myPrint("yellow", "[In] New login request")
                if not self.authentication_login(res['username'], res['password']):
                    continue
                while True:
                    res = self.recieveSocket()
                    if res['command'] == 'clientUdpPort':
                        break
                
                super().updateClientUdpInfo(self.username, self.clientAddress, res['clientUdpPort'])
                myPrint("yellow", f"[In] Update user's UDP port {res['clientUdpPort']} for {self.username}")
                self.insertEdgeDeviceLog()
                
            
            ##### logout ######
            elif res['command'] == 'logout':
                myPrint("yellow", f"[In] New logout request from {self.username}")
                super().removeActiveUser(self.username)
                self.removeEdgeDeviceLog()
            
            ######  AED  ######
            elif res['command'] == 'AED':
                myPrint("yellow", f"[In] New AED request from {self.username}")
                log = self.readEdgeDeviceLog()
                if log == []:
                    log = ["No active device currently connected to IoT Edge network."]
                self.sendSocket({
                    "command": "respondAED",
                    "respond": log
                })

            
            ######  UED  ######
            elif res['command'] == 'UED':
                myPrint("yellow", f"[In] New UED request from {self.username}")
                myPrint("yellow", "[In] Beginning to download data file...")
                self.lock.acquire()
                with open(f"{self.username}-{res['fileID']}.txt", "wb+") as f:
                    recvSize = 0
                    bar = tqdm(total=res['fileSize'])
                    while recvSize < res['fileSize']:
                        line = self.clientSocket.recv(1024)
                        f.write(line)
                        recvSize += len(line)
                        bar.update(len(line))
                    bar.clear()
                    bar.close()
                self.lock.release()
                myPrint("green", f"[Out] Download completed. File {self.username}-{res['fileID']}.txt is saved in the current directory.")
                self.sendSocket({
                    "command": "UEDResponse"
                })
                self.addLog("upload_log.txt", res['fileID'], res['dataAmount'])
            
            
            ######  DTE  ######
            elif res['command'] == 'DTE':
                myPrint("yellow", f"[In] New DTE request from {self.username}")
                if os.path.exists(f"{self.username}-{res['fileID']}.txt"):
                    self.lock.acquire()
                    os.remove(f"{self.username}-{res['fileID']}.txt")
                    self.lock.release()
                    self.addLog("deletion_log.txt", res['fileID'], self.getDataAmount(res['fileID']))
                    myPrint("green", f"[Out] File with ID of {res['fileID']} has been successfully deleted.")
                    self.sendSocket({
                        "command": "DTEResponse",
                        "response": "1"
                    })
                
                else:
                    myPrint("red", f"[Out] Respond to {self.username} that the file with ID of {res['fileID']} does not exist at the server side.")
                    self.sendSocket({
                        "command": "DTEResponse",
                        "response": "0"
                    })
            
            ######  SCS  ######
            elif res['command'] == 'SCS':
                myPrint("yellow", f"[In] New SCS request from {self.username}")
                
                if os.path.exists(f"{self.username}-{res['fileID']}.txt"):
                    result = None
                    lines = []
                    self.lock.acquire()
                    with open(f"{self.username}-{res['fileID']}.txt", 'r', encoding='utf-8') as f:
                        lines = [int(l.strip()) for l in f if l.strip().isalnum()]
                    self.lock.release()
                    
                    if res['computationOperation'] == "SUM":
                        result = sum(lines)
                    elif res['computationOperation'] == "AVERAGE":
                        result = sum(lines) / len(lines)
                    elif res['computationOperation'] == "MAX":
                        result = max(lines)
                    elif res['computationOperation'] == "MIN":
                        result = min(lines)
                    
                    myPrint("green", "[Out] End of calculation, send to user.")
                    
                    self.sendSocket({
                        "command": "SCSResponse",
                        "response": "1",
                        "result": result
                    })
                
                else:
                    myPrint("red", f"[Out] Respond to {self.username} that the file with ID of {res['fileID']} does not exist at the server side.")
                    self.sendSocket({
                        "command": "SCSResponse",
                        "response": "0"
                    })
                    
            ######  UVF  ######
            elif res['command'] == 'UVF':
                myPrint("yellow", f"[In] New UVF request from {self.username}")
                
                if super().isUserActive(res['deviceName']):
                    myPrint("green", f"[Out] Respond to {self.username} that the user {res['deviceName']} is online.")
                    udpInfo = super().getClientUdpInfo(res['deviceName'])
                    self.sendSocket({
                        "command": "UVFResponse",
                        "response": "1",
                        "clientUdpHost": udpInfo[0][0],
                        "clientUdpPort": udpInfo[1]
                    })
                    
                else:
                    myPrint("red", f"[Out] Respond to {self.username} that the Device {res['deviceName']} is currently offline.")
                    self.sendSocket({
                        "command": "UVFResponse",
                        "response": "0"
                    })

    def addLog(self, logFile, fileID, dataAmount):
        self.lock.acquire()
        # Open the file in append mode, if the file does 
        # not exist create a new file in read/write mode
        with open(logFile, "a+", encoding="utf-8") as f:
            f.writelines(f"{self.username}; {datetime.now().strftime('%d %B %Y %H:%M:%S')}; {fileID}; {dataAmount}\n")
        self.lock.release()
    
    def blockTimer(self, username):
        super().removeBlockedUser(username)
        myPrint("green", f"[Out] Times UP, Unblock the user {self.username}")
    
    def readEdgeDeviceLog(self):
        self.lock.acquire()
        result = []
        with open("edge_device_log.txt", "r", encoding="utf-8") as f:
            lines = f.readlines()
            result.extend(f"{line.split(';')[2].strip()}; {line.split(';')[3].strip()}; {line.split(';')[4].strip()}; active since {line.split(';')[1].strip()}" for line in lines if line.split(';')[2].strip() != self.username)
        self.lock.release()
        return result
    
    def insertEdgeDeviceLog(self):
        self.lock.acquire()
        if os.path.exists('edge_device_log.txt'):
            with open("edge_device_log.txt", "r", encoding="utf-8") as f:
                count = len(f.readlines())
        else:
            count = 0
        # Open the file in append mode, if the file does 
        # not exist create a new file in read/write mode
        with open("edge_device_log.txt", "a+", encoding="utf-8") as f:
            f.writelines(f"{count+1}; {datetime.now().strftime('%d %B %Y %H:%M:%S')}; {self.username}; {self.clientAddress[0]}; {super().getClientUdpInfo(self.username)[1]}\n")
        self.lock.release()
    
    def removeEdgeDeviceLog(self):
        self.lock.acquire()
        with open("edge_device_log.txt", "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in lines:
                if self.username in line:
                    lines.remove(line)
                    break
            # update the first sequence number
            for idx, line in enumerate(lines):
                lines[idx] = str(idx+1) + line[1:]

        os.remove("edge_device_log.txt")
        with open("edge_device_log.txt", "w+", encoding="utf-8") as f:
            for line in lines:
                f.writelines(line)
        self.lock.release()
    
    def authentication_login(self, username, password):
        success = False
        self.username = username

        if not self.isValidUsername(username):
            res = '0'
            myPrint("red", "[Out] Invalid username")
            
        elif super().isUserBlocked(username):
            res = '-4'
            myPrint("red", "[Out] Trying to log in with a blocked username")
        
        elif not self.isValidPassword(username, password) and self.numAttempts+1 == self.getMaxAttempts():
            res = '-2'
            self.numAttempts = 0 
            myPrint("red", f"[Out] Invalid Password 3 times, block the user {self.username}.")
            super().addBlockedUser(username)
            timer = threading.Timer(10.0, self.blockTimer, args=(username,))
            timer.start()
        
        elif not self.isValidPassword(username, password):
            res = '-1'
            self.numAttempts += 1
            myPrint("red", "[Out] Invalid Password")
        
        elif self.isUserActive(username):
            res = '-3'
            myPrint("red", "[Out] Trying to log in with an already logged in username")
        
        else:
            res = '1'
            super().addActiveUser(username)
            myPrint("green", f"[Out] User {username} Login successfully!")
            success = True

        self.sendSocket({
            "command": "loginResponse",
            "response": res
        })
        
        return success