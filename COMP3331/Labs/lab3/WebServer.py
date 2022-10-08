# Python 3

import sys, re, os
from threading import Thread
from socket import *


def myTcp(sock: socket, addr):
    print("Accept new connection from %s:%s" % addr)
    request = sock.recv(1024).decode('utf-8').split('\n')
    if "GET" in request[0]:
        
        file = re.search(r'GET\s+\/(.*)\s+HTTP', request[0])[1]
        
        if '.html' in file and os.path.exists(file):
            sock.send("HTTP/1.1 200 OK\r\n".encode('utf-8'))
            sock.send("Content-Type: text/html\r\n\r\n".encode('utf-8'))
            with open(file, 'rb') as f:
                sock.send(f.read())
        elif '.png' in file and os.path.exists(file):
            sock.send("HTTP/1.1 200 OK\r\n".encode('utf-8'))
            sock.send("Content-Type: image/png\r\n\r\n".encode('utf-8'))
            with open(file, 'rb') as f:
                sock.send(f.read())
        else:
            sock.send("HTTP/1.1 404 Not Found\r\n\r\n".encode('utf-8'))

    sock.close()
    print("Connection Close")


serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(('localhost', int(sys.argv[1])))
serverSocket.listen(5)
print("The server is ready to receive")
print("wait for connection...")

while True:
    connectionSocket, address = serverSocket.accept()
    t = Thread(target=myTcp, args=(connectionSocket, address))
    t.start()
