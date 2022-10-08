# python3

import contextlib
import time
from socket import *
from datetime import datetime

def pingRequest(seq):
    serverName = 'localhost'
    serverPort = 3333
    message = f"PING {seq} {time.time()}\r\n"

    clientSocket = socket(AF_INET, SOCK_DGRAM)
    clientSocket.settimeout(0.6)

    clientSocket.sendto(message.encode('utf-8'), (serverName, serverPort))

    with contextlib.suppress(Exception):
        clientSocket.recvfrom(2048)

    clientSocket.close()
    return time.time()

dic = []

for i in range(15):
    t1 = time.time()
    t2 = pingRequest(f"{3331+i}")
    rtt = (datetime.fromtimestamp(t2) - datetime.fromtimestamp(t1)).microseconds/1000.0
    res = f"rtt = {rtt} ms" if rtt < 600 else "time out"
    print(f"ping to 127.0.0.1, seq = {i+1}, {res}")
    if rtt < 600:
        dic.append(rtt)


print(f"min = {min(dic)} ms")
print(f"max = {max(dic)} ms")
print(f"avg = {round(sum(dic)/len(dic),2)} ms")