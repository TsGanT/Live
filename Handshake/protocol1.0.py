from playground.network.common.Protocol import StackingProtocolFactory, StackingProtocol, StackingTransport
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, UINT8, BUFFER, UINT32, BOOL
from playground.network.packet.fieldtypes.attributes import Optional
import random
import logging
import time
import asyncio
import binascii

logger = logging.getLogger("playground.__connector__." + __name__)


## Pre-defined packet class in PRFC
class PoopPacketType(PacketType):
    DEFINITION_IDENTIFIER = "poop"
    DEFINITION_VERSION = "1.0"


class DataPacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.datapacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("seq", UINT32({Optional: True})),
        ("hash", UINT32),
        ("data", BUFFER({Optional: True})),
        ("ACK", UINT32({Optional: True}))

    ]


class HandshakePacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.handshakepacket"
    DEFINITION_VERSION = "1.0"

    NOT_STARTED = 0
    SUCCESS = 1
    ERROR = 2

    FIELDS = [
        ("status", UINT8),
        ("SYN", UINT32({Optional: True})),
        ("ACK", UINT32({Optional: True})),
        ("error", STRING({Optional: True})),
        ("last_valid_sequence", UINT32({Optional: True}))
    ]


class StartupPacket(HandshakePacket):
    DEFINITION_IDENTIFIER = "poop.startuppacket"
    DEFINITION_VERSION = "1.0"


class ShutdownPacket(HandshakePacket):
    DEFINITION_IDENTIFIER = "poop.shutdownpacket"
    DEFINITION_VERSION = "1.0"


# inherit the StackingTransport
class PoopTransport(StackingTransport):
    def create_protocol(self, protocol):
        self.protocol = protocol    #这个protocol是哪里来的呢？

    # overwrite the write() and close()
    def write(self, data):
        self.protocol.send(data)

    def close(self):
        self.protocol.shut()    #老师的码代中间有的，可以去网站上看一下


class POOPProtocol(StackingProtocol):
    def __init__(self, mode):
        super().__init__()      #这个地方为啥非要调用父类的init呢 ？因为父类当中还有需要用到的init的attribute
        self._mode = mode
        self.loop = asyncio.get_event_loop()  # define an async function to check the time out
        self.status = 0  # initiate the status and use the status to control the protocol procedure
        self.SYN = 0
        self.FIN = 0
        self.last_recv_time = 0  # initiate the time of the last packet received
        self.handshake_last_time = 0  # initiate the time of handshake
        self.transport = None  # initiate the current layer transport first
        self.higher_transport = None  # initiate the higher layer transport first
        self.next_seq = 0  # initiate the sequence number of next packet
        self.next_expected_ack = 0  # initiate the expected ack number of next packet
        self.recv_next = 0
        self.send_window = []  # the send window
        self.send_wind_size = 10  # define the window size of send window
        self.send_buffer = []  # the current data buffer
        self.deserializer = PoopPacketType.Deserializer()

    def connection_made(self, transport):
        logger.debug("{} Poop connection made. Calling connection made higher.".format(self._mode))
        self.last_recv_time = time.time()  # define the time of last packet received when connection made
        self.loop.create_task(self.check_connection_timeout()) #loop1
        self.transport = transport
        self.higher_transport = PoopTransport(transport)
        self.higher_transport.create_protocol(self) #这个self有什么用呢？意思是创建当前的protocol， POOPProtocol

        # At initialization, the client will set its SYN to be any random value between 0 and 2^32, server will set
        # its SYN anything between 0 and 2^32 and its ACK any random value between 0 and 2^32
        if self._mode == "client":  #这个地方还没有写完
            packet = StartupPacket()
            # The client needs to send a packet with SYN and status NOT STARTED to the server to request a connection.
            self.CSYN = random.randint(0, 2 ** 32)  # random value between 0 and 2**32
            packet.SYN = self.CSYN
            packet.status = 0  # the status should be "NOT_STARTED" at the beginning
            transport.write(packet.__serialize__())

            # mark down the time
            self.handshake_last_time = self.loop.create_task(self.check_handshake_connection_timeout()) #loop2

    def data_received(self, buffer):
        logger.debug("{} passthrough received a buffer of size {}".format(self._mode, len(buffer)))
        self.deserializer.update(buffer)

        for packet in self.deserializer.nextPackets():  #在这个地方进行了统一的deserializer
            print(packet)
            if packet.DEFINITION_IDENTIFIER == "poop.startuppacket":
                self.handshake_recv(packet)
            elif packet.DEFINITION_IDENTIFIER == "poop.datapacket":
                self.datapacket_recv(packet)
            elif packet.DEFINITION_IDENTIFIER == "poop.shutdownpacket":
                self.shutdown_recv(packet)

    def connection_lost(self, exc):
        logger.debug("{} passthrough connection lost. Shutting down higher layer.".format(self._mode))
        self.higherProtocol().connection_lost(exc)

    # --------------------------------------------------------------------------------------------------------
    def handshake_recv(self, packet):
        logger.debug("{} received a handshake packet".format(self._mode))
        if self._mode == "server":
            if packet.status == 0:
                if packet.SYN:
                    # Upon receiving packet, the server sends back a packet with random number from 0 to 2^32,
                    # ACK set to (SYN+1)%(2^32)and status SUCCESS.
                    new_packet = StartupPacket()
                    # get a random ACK and assign the value to SYN
                    self.SSYN = random.randint(0, 2 ** 32)
                    new_packet.SYN = self.SSYN
                    # make the ack + 1
                    new_packet.ACK = (packet.SYN + 1) % (2 ** 32)
                    new_packet.status = 1
                    self.transport.write(new_packet.__serialize__())
                else:
                    new_packet = StartupPacket()
                    new_packet.status = 2
                    new_packet.error = "No SYN received!"
                    self.transport.write(new_packet.__serialize__())

            elif packet.ACK == (self.SSYN + 1) % (2 ** 32):
                # Upon receiving the SUCCESS packet, the server checks if ACK is old ACK plus 1. If success, the server
                # acknowledges this connection. Else, the server sends back a packet to the client with status
                # ERROR.
                # All agents set the sequence number on the first packet they send to be the random value
                # they generated during the course of the Handshake Protocol.
                self.next_seq = self.SSYN
                self.last_recv_time = time.time()
                self.next_expected_ack = self.SSYN

                self.higherProtocol().connection_made(self.higher_transport)    #此时的握手已经完成，那么上层协议可以使用transport
                logger.debug("Server Poop handshake success!")

            else:
                new_packet = StartupPacket()
                new_packet.status = 2
                # new_packet.ACK = packet.SYN
                new_packet.error = "The ACK doesn't match! Server Connection Lost!"
                self.transport.write(new_packet.__serialize__())

        elif self._mode == "client":
            # Upon receiving the SUCCESS packet, the client checks if new ACK is old SYN + 1. If it is correct,
            # the client sends back to server a packet with ACK set to (ACK+1)%(2^32)  and status SUCCESS and acknowledge this
            # connection with server. Else, the client sends back to server a packet with status set to ERROR.
            if packet.ACK == (self.CSYN + 1) % (2 ** 32):
                new_packet = StartupPacket()
                new_packet.SYN = (packet.ACK + 1) % (2 ** 32)
                new_packet.ACK = (packet.SYN + 1) % (2 ** 32)
                new_packet.status = 1
                self.transport.write(new_packet.__serialize__())
                # All agents set the sequence number on the first packet they send to be the random value
                # they generated during the course of the Handshake Protocol.
                self.next_seq = self.CSYN
                self.last_recv_time = time.time()
                self.next_expected_ack = self.CSYN

                self.higherProtocol().connection_made(self.higher_transport)
                logger.debug("Client Poop handshake success!")

            else:
                new_packet = StartupPacket()
                new_packet.status = 2
                # new_packet.ACK = packet.SYN
                new_packet.error = "The ACK doesn't match!  Client Connection Lost!"  #这个地方多send一个error
                self.transport.write(new_packet.__serialize__())

        elif self.status == 2:  #反正我就是错了，给一个error
            logger.debug("{} received an error packet".format(self._mode))

    async def check_handshake_connection_timeout(self):
        while True:
            if time.time() - self.last_recv_time > 10:
                logger.debug("NO Data Transferring for a long time! Dropped!")
                # Reset the connection
                new_packet = StartupPacket()
                new_packet.SYN = self.CSYN
                new_packet.status = 0
                self.transport.write(new_packet.__serialize__())
            await asyncio.sleep(10 - (time.time() - self.last_recv_time))   #讲道理这里可以加一个绝对值？

    # --------------------------------------------------------------------------------------------------------
    def datapacket_recv(self, packet):  #这个函数的作用就是通过序列号是否完整来判断对方是否收到了所有的发出去的包，如果是，则发送下一个包，如果没有那么就按照没有收到（丢失）的包的序列好请求retransmit
        # Drop if not a datapacket
        if packet.DEFINITION_IDENTIFIER != "poop.datapacket":   #这里为什么要多判断一次呢？
            logger.debug("Not the expected data packet. Dropped!")
            return

        # If ACK is set, handle ACK
        if packet.ACK:
            # Check hash, drop if invalid
            tmp_packet = DataPacket(ACK=packet.ack, hash=0)
            if binascii.crc32(tmp_packet.__serialize__()) & 0xffffffff != packet.hash:  #校验了一下收到的包是需要的包
                return  #对这个return的理解有点模糊
            # If ACK matches sequence of a packet in send queue, take off of send queue, and update send queue
            self.send_window[:] = [send_pkt for send_pkt in self.send_window if send_pkt.seq != packet.ack] #将send window中的没有接收到的包保存在send window当中

            if self.send_window:
                self.next_expected_ack = self.send_window[0].seq    #把第一个序列发出去要再发一次这个包（receive中，ACK = Seq， 也只有这样才能判断哪个包收到哪个包没有）
            else:
                self.next_expected_ack = packet.ACK + 1     #如果window中没有包，也就是所有的包按顺序都到达了，那就发送下一个序列号的包
            self.send_packets_inqueue()
            return



    def send(self,data):
        self.send_buffer = self.buffer + data
        self.send_packets_inqueue()

    def send_packets_inqueue(self):
        while self.send_buffer and len(self.send_window) <= self.send_wind_size and self.next_seq < self.next_expected_ack + self.send_wind_size:
            #这句话需要满足的条件是，1: 要有data需要send， 2: send window size有空间，然后对方需要接受的都接受了需要下一个包， 但是+不懂
            if len(self.send_buffer) >= 15000:
                new_packet = DataPacket()
                new_packet.seq = self.next_seq
                new_packet.data = bytes(self.send_buffer[0:15000])  #也就是说我每15000个二进制数进行一次截取
                new_packet.hash = 0
                new_packet.hash = binascii.crc32(new_packet.__serialize__()) & 0xffffffff   #将整个包进行c2c32获取校验值，（0xffffffff）可用于生成相同的数值，其实就是一个校验运算而已
                # set the send_buffer containing the part of data which larger than 15000
                self.send_buffer = self.send_buffer[15000:]     #去掉刚刚发送的15000个二进制数
            else:
                new_packet = DataPacket()
                new_packet.seq = self.next_seq
                new_packet.data = bytes(self.send_buffer[0:len(self.send_buffer)]) #将剩下的全部都发出去
                new_packet.hash = 0         #为什么这个hash要先等于0然后再对整个packet取hash值呢？
                new_packet.hash = binascii.crc32(new_packet.__serialize__()) & 0xffffffff
                # set the send_buffer to be empty again
                self.send_buffer = []   #发完啦

            if self.recv_next == 2**32:     #当序列号用完了，我们从头再来
                self.recv_next = 0

            else:
                self.next_seq = self.next_seq + 1       #没用完将下一个包的序列号设置为上一个加一

            self.send_queue.append(new_packet)
            self.transport.write(new_packet.__serialize__())

#包
#shut
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

