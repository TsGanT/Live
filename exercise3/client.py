from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER, BOOL
import asyncio
import time
import playground
from autograder_ex6_packets import AutogradeStartTest
from autograder_ex6_packets import AutogradeTestStatus
from field import GameCommandPacket
from field import GameResponsePacket


class EchoClientProtocol(asyncio.Protocol):
    """
    This is our class for the Client's protocol. It provides an interface
    for sending a message. When it receives a response, it prints it out.
    """
    def __init__(self):
        self.deserializer = GameCommandPacket.Deserializer()
        #self.loop=loop
        self.i=0
        self.list=[  "look mirror","get hairpin", 
                     "unlock chest with hairpin", "open chest", "get hammer in chest","hit flyingkey with hammer",
                     "get key","unlock door with key", "open door","",""]        
        
    def connection_made(self, transport):
        self.transport = transport
        print("Connected to {}".format(transport.get_extra_info("peername")))
        packet1 = AutogradeStartTest(name="Shi Tang", email="stang47@jhu.edu", team=4, port=2001)
        with open("field.py", "rb") as f:
            packet1.packet_file = f.read()
        self.transport.write(packet1.__serialize__())
               
    def data_received(self, data):
        #self.deserializer.update(data)
        self.deserializer.update(data)
        for echoPacket in self.deserializer.nextPackets():
            if echoPacket.original == False:
                    #self.callback(echoPacket.message)
                flag = echoPacket.responsee.split(" ")
                if self.i != 6:
                    print(self.list[self.i])
                    commond=self.send_message(self.list[self.i])
                    self.send(commond)
                    self.i+=1  
                else:
                    if flag[1] == "hit":
                        print(self.list[self.i])
                        commond=self.send_message(self.list[self.i])
                        self.send(commond)
                        self.i+=1  
                    else:
                        self.i=self.i-1
                        print(self.list[self.i])
                        commond=self.send_message(self.list[self.i])
                        self.send(commond)
                        time.sleep(1)
                        self.i=self.i+1
            else:
                print("Got a message from server marked as original. Dropping.")
                

    def send_message(self, message):
        command = message + "<EOL>\n"
        return command
        
    def send(self, data):
        echoPacket = GameCommandPacket(message=data)        
        self.transport.write(echoPacket.__serialize__())

if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = playground.create_connection(EchoClientProtocol,'20194.0.0.19000', 19006)
	client = loop.run_until_complete(coro)

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass

	loop.close()
