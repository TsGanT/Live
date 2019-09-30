from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER, BOOL
import asyncio
import time
import playground
from autograder_ex6_packets import AutogradeStartTest
from autograder_ex6_packets import AutogradeTestStatus
from field import *
from bank_hello_world import *


class EchoClientProtocol(asyncio.Protocol):
    """
    This is our class for the Client's protocol. It provides an interface
    for sending a message. When it receives a response, it prints it out.
    """

    def __init__(self):
        self.deserializer = PacketType.Deserializer()
        self.i = 0
        self.list = ["look mirror", "get hairpin",
                     "unlock chest with hairpin", "open chest", "get hammer in chest", "hit flyingkey with hammer",
                     "get key","unlock door with key", "open door"]
        # loop.set_debug(enabled=True)
        # from playground.common.logging import EnablePresetLogging, PRESET_DEBUG
        # EnablePresetLogging(PRESET_DEBUG)

    def connection_made(self, transport):
        self.transport = transport
        print("Connected to {}".format(transport.get_extra_info("peername")))
        packet1 = AutogradeStartTest(
            name="Shi Tang", email="stang47@jhu.edu", team=4, port=2001)
        with open("field.py", "rb") as f:
            packet1.packet_file = f.read()
        self.transport.write(packet1.__serialize__())

        self.command_packet = GameCommandPacket.create_game_command_packet("Submit")
        self.transport.write(self.command_packet.__serialize__())

    def data_received(self, data):
        self.deserializer.update(data)
        for echoPacket in self.deserializer.nextPackets():
            if isinstance(echoPacket, AutogradeTestStatus):
                print(echoPacket.client_status)
                print(echoPacket.server_status)
                print(echoPacket.error)

            if isinstance(echoPacket, GameResponsePacket):
                print(echoPacket.responsee)
                flag = echoPacket.responsee.split(" ")
                if flag[-1] == "floor" or flag[-1] == "ceiling" or flag[-1] == "wall":
                    continue
                if self.i <= len(self.list)-1:
                    if self.i != 6:
                        print(self.list[self.i])
                        commond = self.list[self.i]
                        self.send(commond)
                        self.i =self.i + 1
                    else:
                        if flag[1] == "hit":
                            continue
                        if flag[1] == "flying":
                            print(self.list[self.i])
                            commond = self.list[self.i]
                            self.send(commond)
                            self.i += 1
                        else:
                            self.i = self.i-1
                            print(self.list[self.i])
                            commond = self.list[self.i]
                            self.send(commond)
                            time.sleep(1)
                            self.i = self.i+1

    def send(self, data):
        g = GameCommandPacket()
        ePacket = g.create_game_command_packet(data)
        self.transport.write(ePacket.__serialize__())
    
    async def CreatePayment(self, account, amount, unique_id):
        result = await paymentInit("stang_47", account, amount, unique_id)
        print(result)
        receipt, receipt_sig = result
        game_packet = create_game_pay_packet(receipt, receipt_sig)
        self.transport.write(game_packet.__serialize__())
    
    def connection_lost(self, exc):
        print('The server closed the connection')
        print('Stop the event loop')
        self.loop.stop()


if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = playground.create_connection(
	EchoClientProtocol, '20194.0.0.19000', 19007)
	client = loop.run_until_complete(coro)
	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass

	loop.close()
