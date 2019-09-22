from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER, BOOL
import asyncio
import time
import playground
import autograder_ex6_packets

list=  ["SUBMIT,Shi Tang,stang47@jhu.edu,team 4,2001", "look mirror","get hairpin", 
        "unlock chest with hairpin", "open chest", "get hammer in chest","hit flyingkey with hammer",
        "get key","unlock door with key", "open door"] 

class EchoPacket(PacketType):
    DEFINITION_IDENTIFIER = "test.EchoPacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
              ("original", BOOL),
              ("message", STRING)
             ]
class EchoClientProtocol(asyncio.Protocol):
    """
    This is our class for the Client's protocol. It provides an interface
    for sending a message. When it receives a response, it prints it out.
    """
    def __init__(self, callback=None):
        self.buffer = ""
        if callback:
            self.callback = callback
        else:
            self.callback = print
        self.transport = None
        self.deserializer = EchoPacket.Deserializer()
        #self.loop=loop
        self.i=0
        self.list=["SUBMIT,Shi Tang,stang47@jhu.edu,team 4,2001", "look mirror","get hairpin", 
                     "unlock chest with hairpin", "open chest", "get hammer in chest","hit flyingkey with hammer",
                     "get key","unlock door with key", "open door","",""] 
        
    def close(self):
        self.__sendMessageActual("__QUIT__")
        
    def connection_made(self, transport):
        print("Connected to {}".format(transport.get_extra_info("peername")))
        packet1 = AutogradeStartTest()
        packet1.name = "Shi Tang"
        packet1.team = "team4"
        packet1.email = "stang47@jhu.edu"
        packet1.port = 2001
        packet1.packet_file = b""
        self.transport.write(packet1.__serialize__())
        self.transport = transport
        
    def data_received(self, data):
        self.deserializer.update(data)
        for echoPacket in self.deserializer.nextPackets():
            if echoPacket.original == False:
                self.callback(echoPacket.message)
                flag = echoPacket.message.split(" ")
                if self.i != 7:
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
                        time.sleep(2)
                        self.i=self.i+1
            else:
                print("Got a message from server marked as original. Dropping.")
                

    def send_message(self, message):
        command = message + "<EOL>\n"
        return command
        
    def send(self, data):
        echoPacket = EchoPacket(original=True, message=data)
        
        self.transport.write(echoPacket.__serialize__())

if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = playground.create_connection(EchoEchoClientProtocol,'20194.0.0.19000', 19006)
	client = loop.run_until_complete(coro)

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass

	loop.close()
