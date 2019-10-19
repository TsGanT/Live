from playground.network.common.Protocol import StackingProtocolFactory, StackingProtocol, StackingTransport
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, UINT8, BUFFER, UINT16, BOOL
import logging
from playground.network.packet.fieldtypes.attributes import Optional
import random

logger = logging.getLogger("playground.__connector__." + __name__)

a = random.randint(0,254)
print(a)
class HandshakePacket(PacketType):
    DEFINITION_IDENTIFIER = "handshakepacket"
    DEFINITION_VERSION = "1.0"
    NOT_STARTED = 0
    SUCCESS = 1
    ERROR = 2
    FIELDS = [
        ("SYN", UINT8({Optional: True})),
        ("ACK", UINT8({Optional: True})),
        ("status", UINT8),
        ("error", STRING({Optional: True}))
    ]


class PassthroughProtocol(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        self._mode = mode
        self.flag = 0

    def connection_made(self, transport):
        logger.debug("{} passthrough connection made. Calling connection made higher.".format(self._mode))
        self.transport = transport
        packet = HandshakePacket()
        # At initialization, the client will set its SYN to be any random value between 0 and 254, server will set
        # its SYN anything between 0 and 254 and its ACK any random value between 1 and 254.
        if self._mode == "client":
            # The client needs to send a packet with SYN and status NOT STARTED to the server to request a connection.
            self.SYN = a
            packet.SYN = self.SYN
            packet.status = 0
            # packet.ACK = 1  # should be modified to random number 1~255
            transport.write(packet.__serialize__())
        
        if self._mode == "server":
            # The client needs to send a packet with SYN and status NOT STARTED to the server to request a connection.
            self.SYN = a
            packet.SYN = self.SYN
            packet.status = 0


    def data_received(self, buffer):
        logger.debug("{} passthrough received a buffer of size {}".format(self._mode, len(buffer)))
        # after handshake successfully, the deserializer should be changed
        if self.flag == 0:
            self.buffer = HandshakePacket.Deserializer()
            self.buffer.update(buffer)
        else:
            self.buffer = PacketType.Deserializer()#当flag=1时，就已经是正常的包了
            self.buffer.update(buffer)

        for packet in self.buffer.nextPackets():
            print(packet)
            if self._mode == "server" and isinstance(packet, HandshakePacket):
                if packet.status == 0:
                    # Upon receiving packet, the server sends back a packet with SYN+1, ACK set to 0 and status SUCCESS.
                    new_packet = HandshakePacket()
                    new_packet.SYN = packet.SYN + 1
                    new_packet.ACK = 0
                    new_packet.status = 1
                    self.transport.write(new_packet.__serialize__())
                elif packet.ACK == 1 and packet.SYN == self.syn +2:
                    # Upon receiving the SUCCESS packet, the server checks if ACK is 1. If success, the server
                    # acknowledges this connection. Else, the server sends back a packet to the client with status
                    # ERROR.
                    higher_transport = StackingTransport(self.transport)
                    self.higherProtocol().connection_made(higher_transport)
                    self.flag = 1
                else:
                    new_packet = HandshakePacket()
                    new_packet.status = 2
                    self.transport.write(new_packet.__serialize__())

            elif self._mode == "client" and isinstance(packet, HandshakePacket):
                # Upon receiving the SUCCESS packet, the client checks if new SYN is old SYN + 1. If it is correct,
                # the client sends back to server a packet with ACK set to 1 and status SUCCESS and acknowledge this
                # connection with server. Else, the client sends back to server a packet with status set to ERROR.
                if packet.SYN == self.SYN + 1:
                    new_packet = HandshakePacket()
                    new_packet.SYN = packet.SYN + 1
                    new_packet.ACK = 1
                    new_packet.status = 1
                    self.flag = 1
                    self.transport.write(new_packet.__serialize__())
                    higher_transport = StackingTransport(self.transport)
                    self.higherProtocol().connection_made(higher_transport)
                else:
                    new_packet = HandshakePacket()
                    new_packet.status = 2
                    self.transport.write(new_packet.__serialize__())
            else:
                self.higherProtocol().data_received(buffer)

    def connection_lost(self, exc):
        logger.debug("{} passthrough connection lost. Shutting down higher layer.".format(self._mode))
        self.higherProtocol().connection_lost(exc)


# from playground.network.common import StackingProtocolFactory
#
# PassthroughFactory = StackingProtocolFactory.CreateFactoryType(PassthroughProtocol)
# factory1 = PassthroughFactory()

PassthroughClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="client")
)

PassthroughServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="server")
)
