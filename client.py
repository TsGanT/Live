from socket import *

HOST='192.168.200.52'
PORT=19001
BUFSIZE=1024
ADDR=(HOST, PORT)
s=socket.socket()
"""CliSock=socket(AF_INET, SOCK_STREAM)"""
s.connect(ADDR)

"""print("Hi my dear worrior, welcome to this game. You are now been bangjia in the room")
print("In this game you can only input the name of items and")
print("input the behaviour like look, use and get")
print("You have to escape from the room in 10mins or you will die.")
print("I wish you have a good luck!")
print("please enter s to star the game!")"""
"""while True:
    data=input(">>")
    date=str.encode(data)
    if not data:
        break
    CliSock.send(date)
    data=CliSock.recv(BUFSIZE)
    date=bytes.decode(data)
    if not data:
        break
    print(date)"""

list=["Shi Tang","look mirror","get hairpin","unlock door with hairpin","open door"]

while True:
    aa=s.recv(1024)
    if not aa:
        break
    else:
        b=aa.decode()
        print(b)
        i=0
        n=list[i].encode()
        s.send(n)
        i=i+1

s.close()

