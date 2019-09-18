"""import socket
import time

HOST='192.168.200.52'
PORT=19002
BUFSIZE=1024
ADDR=(HOST, PORT)
s=socket.socket()
CliSock=socket(AF_INET, SOCK_STREAM)
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

s.close()"""

import asyncio
import time
import playground

list=  ["SUBMIT,Shi Tang,stang47@jhu.edu,team 4,2001", "look mirror","get hairpin", 
        "unlock chest with hairpin", "open chest", "get hammer in chest","hit flyingkey with hammer",
        "get key","unlock door with key", "open door"] 


class EchoClient(asyncio.Protocol):
    
    def __init__(self):
        self.loop=loop
        self.i=0
        self.list=["SUBMIT,Shi Tang,stang47@jhu.edu,team 4,2001", "look mirror","get hairpin", 
                     "unlock chest with hairpin", "open chest", "get hammer in chest","hit flyingkey with hammer",
                     "get key","unlock door with key", "open door","",""] 
        

    def connection_made(self, transport):
        self.transport=transport
        self.transport.write(("<EOL>\n").encode())

    def data_received(self, data):
        print(data.decode())
        result = data.decode()
        flag = result.split(" ")

        if self.i != 7:
            print(self.list[self.i])
            commond=self.send_message(self.list[self.i])
            self.transport.write(commond.encode())
            self.i+=1  
        else:
            if flag[1] == "hit":
                print(self.list[self.i])
                commond=self.send_message(self.list[self.i])
                self.transport.write(commond.encode())
                self.i+=1  
            else:
                self.i=self.i-1
                print(self.list[self.i])
                commond=self.send_message(self.list[self.i])
                self.transport.write(commond.encode())
                time.sleep(2)
                self.i=self.i+1
    

    def send_message(self, message):
        command = message + "<EOL>\n"
        return command

    def connection_lost(self, exc):
        print('The server closed the connection')
        print('Stop the event loop')
        self.loop.stop()
    



if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = playground.create_connection(EchoClient,'20194.0.0.19000', 19005)
	client = loop.run_until_complete(coro)

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass

	loop.close()
