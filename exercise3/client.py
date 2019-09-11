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

class EchoClient(asyncio.Protocol):
    def __init__(self):
        self.loop=loop

    def connection_made(self, transport):
        self.transport=transport

    def data_received(self, data):
        print(data.decode())
        result = data.decode()
        flag = result.split(" ")
        if flag[0] == "SUBMIT"：
            list=["SUBMIT,Shi Tang,stang47@jhu.edu,team 4,7074", "look mirror","get hairpin", 
                    "look chest", "unlock chest with hairpin", "open chest", "get hammer in chest",
                    "unlock door with hairpin", "open door"]
            for i in list:
                print(i)
                commond=self.send_message(i)
                self.transport.write(commond.encode())
            
            

    def send_message(self, message):
        command = message + "<EOL>\n"
        return command

    def connection_lost(self, exc):
        print('The server closed the connection')
        print('Stop the event loop')
        self.loop.stop()
    



if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = loop.create_connection(EchoClient,'192.168.200.52', 7074)
	client = loop.run_until_complete(coro)

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass

	client.close()
	loop.run_until_complete(client.close())
	loop.close()
