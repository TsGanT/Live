import socket
import time

HOST='192.168.200.52'
PORT=19002
BUFSIZE=1024
ADDR=(HOST, PORT)
s=socket.socket()
"""CliSock=socket(AF_INET, SOCK_STREAM)"""
s.connect(ADDR)

list=["Shi Tang","look mirror","get hairpin","unlock door with hairpin","open door"]

for i in range(len (list)):
    print(i)
    aa=s.recv(1024)
    b=aa.decode()
    print(b)
    n=list[i].encode()
    s.send(n)
    time.sleep(0.25)
    i=i+1
suc_res = s.recv(1024)
print(suc_res.decode())

s.close()

