'''
Created on Feb 15, 2014

@author: sethjn

This sample shows how to do some basic things with playground.
It does not use the PlaygroundNode interface. To see an example
of that, check out computePi.py.
'''

# We will use "BOOL1" and "STRING" in our message definition
from playground.network.packet.fieldtypes import BOOL, STRING
from playground.network.common import PlaygroundAddress

# MessageDefinition is the base class of all automatically serializable messages
from playground.network.packet import PacketType
import playground

import sys, time, os, logging, asyncio
#logger = logging.getLogger(__name__)

class EchoPacket(PacketType):
    """
    EchoProtocolPacket is a simple message for sending a bit of 
    data and getting the same data back as a response (echo). The
    "header" is simply a 1-byte boolean that indicates whether or
    not it is the original message or the echo.
    """
    
    # We can use **ANY** string for the identifier. A common convention is to
    # Do a fully qualified name of some set of messages.
    DEFINITION_IDENTIFIER = "test.EchoPacket"
    
    # Message version needs to be x.y where x is the "major" version
    # and y is the "minor" version. All Major versions should be
    # backwards compatible. Look at "ClientToClientMessage" for
    # an example of multiple versions
    DEFINITION_VERSION = "1.0"
    FIELDS = [
              ("original", BOOL),
              ("message", STRING)
             ]


class EchoServerProtocol(asyncio.Protocol):
    """
    This is our class for the Server's protocol. It simply receives
    an EchoProtocolMessage and sends back a response
    """
    def __init__(self):
        self.deserializer = EchoPacket.Deserializer()
        self.transport = None
        
    def connection_made(self, transport):
        print("Received a connection from {}".format(transport.get_extra_info("peername")))
        self.transport = transport
        self.game = EscapeRoomGame()
        self.game.output = self.send_message
        self.game.create_game()
        self.game.start()
        self.loop = asyncio.get_event_loop()
        self.loop.create_task(self.agent())
        
    def connection_lost(self, reason=None):
        print("Lost connection to client. Cleaning up.")
        
    def data_received(self, data):
        self.deserializer.update(data)
        for echoPacket in self.deserializer.nextPackets():
            if echoPacket.original:
                print("Got {} from client.".format(echoPacket.message))
                
                if echoPacket.message == "__QUIT__":
                    print("Client instructed server to quit. Terminating")
                    self.transport.close()
                    return
                
                responsePacket = EchoPacket()
                responsePacket.original = False # To prevent potentially infinte loops?牛逼
                responsePacket.message = self.send_message(echoPacket.message)
                
                self.transport.write(responsePacket.__serialize__())                
            else:
                print("Got a packet from client not marked as 'original'. Dropping")

        if self.game.status == "escaped":
            print("Success")
            self.transport.close()

    async def agent(self):
        await asyncio.wait([asyncio.ensure_future(a) for a in self.game.agents])

    def send_message(self,result):
        result = result + "<EOL>\n"
        print(result)
        return result
        
        
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
        
class EchoControl:
    def __init__(self):
        self.txProtocol = None
        
    def buildProtocol(self):
        return EchoClientProtocol(self.callback)
        
    def connect(self, txProtocol):
        self.txProtocol = txProtocol
        print("Echo Connection to Server Established!")
        self.txProtocol = txProtocol
        sys.stdout.write("Enter Message: ")
        sys.stdout.flush()
        asyncio.get_event_loop().add_reader(sys.stdin, self.stdinAlert)
        
    def callback(self, message):
        print("Server Response: {}".format(message))
        sys.stdout.write("\nEnter Message: ")
        sys.stdout.flush()
        
    def stdinAlert(self):
        data = sys.stdin.readline()
        if data and data[-1] == "\n":
            data = data[:-1] # strip off \n
        self.txProtocol.send(data)

        

USAGE = """usage: echotest <mode> [-stack=<stack_name>]
  mode is either 'server' or a server's address (client mode)"""

if __name__=="__main__":
    echoArgs = {}
    
    stack = "default"
    
    args= sys.argv[1:]
    i = 0
    for arg in args:
        if arg.startswith("-"):
            k,v = arg.split("=")
            echoArgs[k]=v
        else:
            echoArgs[i] = arg
            i+=1
            
    if "-stack" in echoArgs:
        stack = echoArgs["-stack"]
    
    if not 0 in echoArgs:
        sys.exit(USAGE)

    mode = echoArgs[0]
    loop = asyncio.get_event_loop()
    loop.set_debug(enabled=True)
    from playground.common.logging import EnablePresetLogging, PRESET_DEBUG
    #EnablePresetLogging(PRESET_DEBUG)
    
    if mode.lower() == "server":
        coro = playground.create_server(lambda: EchoServerProtocol(), port=101, family=stack)
        server = loop.run_until_complete(coro)
        print("Echo Server Started at {}".format(server.sockets[0].gethostname()))
        loop.run_forever()
        loop.close()
        
        
    else:
        remoteAddress = mode
        control = EchoControl()
        coro = playground.create_connection(control.buildProtocol, 
            host=remoteAddress, 
            port=101,
            family=stack)
        transport, protocol = loop.run_until_complete(coro)
        print("Echo Client Connected. Starting UI t:{}. p:{}".format(transport, protocol))
        control.connect(protocol)
        loop.run_forever()
        loop.close()
        