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


class ResendPacket(DataPacket):
    DEFINITION_IDENTIFIER = "poop.resendpacket"
    DEFINITION_VERSION = "1.0"
    TIMESTAMP = 0


class HandshakePacket(PoopPacketType):      #这个地方就不需要start那个packet了，因为这个packet的内容就包括了start中需要的内容
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
    ]

class ShutdownPacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.shutdownpacket"
    DEFINITION_VERSION = "1.0"

    SUCCESS = 0
    ERROR = 1

    FIELDS = [
        ("FIN", UINT32({Optional: True})),
        ("FACK", UINT32({Optional: True}))      #这个FACK要研究一下
    ]


# inherit the StackingTransport
class PoopTransport(StackingTransport):     #太牛逼了，把自己的protocol传上去的方法
    def create_protocol(self, protocol):
        self.protocol = protocol

    # overwrite the write() and close()
    def write(self, data):
        self.protocol.send(data)

    def close(self):
        self.protocol.shut()


class POOPProtocol(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        self._mode = mode
        self.loop = asyncio.get_event_loop()  # define an async function to check the time out
        self.status = 0  # initiate the status and use the status to control the protocol procedure
        self.handshake_flag = 0  # check the handshake flag if it is success or not
        self.CSYN = 0
        self.SSYN = 0
        self.shut_SYN = 0
        self.FIN = 0
        self.last_handshake_time = 0  # initiate the time of the last handshake packet received
        self.last_data_time = 0  # initiate the time of the last data packet received
        self.shutdown_time = 0
        self.check_shutdown_count = 0
        self.handshake_last_time = 0  # initiate the time of handshake, just for debugging
        self.transport = None  # initiate the current layer transport first
        self.higher_transport = None  # initiate the higher layer transport first
        self.next_seq_send = 0  # initiate the sequence number of next packet
        self.next_expected_ack = 0  # initiate the expected ack number of next packet
        self.next_seq_recv = 0
        self.send_window = []  # the send window
        self.recv_window = []  # the recv window
        self.send_window_size = 10  # define the window size of send window
        self.recv_window_size = 10  # define the window size of recv window receive窗口规定一个大小
        self.send_buffer = []  # the current data buffer

        self.deserializer = PoopPacketType.Deserializer()

    def connection_made(self, transport):
        logger.debug("{} Poop connection made. Calling connection made higher.".format(self._mode))
        self.last_handshake_time = time.time()  # define the time of last packet received when connection made
        self.transport = transport
        self.higher_transport = PoopTransport(transport)
        self.higher_transport.create_protocol(self)
        self.loop.create_task(self.resend_check())

        # At initialization, the client will set its SYN to be any random value between 0 and 2^32, server will set
        # its SYN anything between 0 and 2^32 and its ACK any random value between 0 and 2^32
        if self._mode == "client":
            packet = StartupPacket()#还没有改？
            # The client needs to send a packet with SYN and status NOT STARTED to the server to request a connection.
            self.CSYN = random.randint(0, 2 ** 32)  # random value between 0 and 2**32
            packet.SYN = self.CSYN
            packet.status = 0  # the status should be "NOT_STARTED" at the beginning
            transport.write(packet.__serialize__())     #发起第一次握手

            # mark down the time
            self.handshake_last_time = self.loop.create_task(self.check_handshake_connection_timeout())

    def data_received(self, buffer):
        logger.debug("{} passthrough received a buffer of size {}".format(self._mode, len(buffer)))
        self.deserializer.update(buffer)

        for packet in self.deserializer.nextPackets():
            print(packet)
            if packet.DEFINITION_IDENTIFIER == "poop.startuppacket":
                self.handshake_recv(packet)
            elif packet.DEFINITION_IDENTIFIER == "poop.datapacket":
                self.datapacket_recv(packet)
            elif packet.DEFINITION_IDENTIFIER == "poop.shutdownpacket":     #Half open?
                if self.handshake_flag == 1:
                    self.shutdown_recv(packet)
                else:
                    new_packet = HandshakePacket()
                    new_packet.status = 2
                    self.transport.write(new_packet.__serialize__())

    def connection_lost(self, exc):
        logger.debug("{} passthrough connection lost. Shutting down higher layer.".format(self._mode))
        self.higherProtocol().connection_lost(exc)

    # --------------------------------------------------------------------------------------------------------
    def handshake_recv(self, packet):
        self.last_handshake_time = time.time()
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
                    self.transport.write(new_packet.__serialize__())    #收到来自client的第一次握手，然后由server开始发起第二次握手
                else:       #根据要求是要改的
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
                self.next_seq_send = self.SSYN
                self.last_data_time = time.time()
                self.next_expected_ack = self.SSYN
                self.next_seq_recv = packet.SYN - 1
                self.handshake_flag = 1
                self.higherProtocol().connection_made(self.higher_transport)
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
                self.next_seq_send = self.CSYN
                self.last_data_time = time.time()
                self.next_expected_ack = self.CSYN
                self.next_seq_recv = packet.SYN - 1
                self.check_handshake_connection_timeout.cancel()
                self.higherProtocol().connection_made(self.higher_transport)
                logger.debug("Client Poop handshake success!")

            else:
                new_packet = StartupPacket()
                new_packet.status = 2
                # new_packet.ACK = packet.SYN
                new_packet.error = "The ACK doesn't match!  Client Connection Lost!"
                self.transport.write(new_packet.__serialize__())

        elif self.status == 2:
            logger.debug("{} received an error packet".format(self._mode))

    async def check_handshake_connection_timeout(self):
        while True:
            if time.time() - self.last_handshake_time > 10:
                logger.debug("NO Data Transferring for a long time! Dropped!")
                # Reset the connection
                new_packet = StartupPacket()
                new_packet.SYN = self.CSYN
                new_packet.status = 0
                self.transport.write(new_packet.__serialize__())
            await asyncio.sleep(10 - (time.time() - self.last_handshake_time))

    async def check_connection_timeout(self):
        while True:
            if (time.time() - self.last_data_time) > 20:
                # time out after 5 min
                self.status = 0
                self.transport.close()
            await asyncio.sleep(20 - (time.time() - self.last_data_time))

    # --------------------------------------------------------------------------------------------------------
    def send(self, data):
        self.send_buffer = self.buffer + data
        self.send_packets_inqueue()

    def send_packets_inqueue(self):
        while self.send_buffer and len(
                self.send_window) <= self.send_window_size and self.next_seq_send < self.next_expected_ack + self.send_window_size:
            if len(self.send_buffer) >= 15000:
                new_packet = DataPacket()
                new_packet.seq = self.next_seq_send
                new_packet.data = bytes(self.send_buffer[0:15000])
                new_packet.hash = 0
                new_packet.hash = binascii.crc32(new_packet.__serialize__()) & 0xffffffff
                # set the send_buffer containing the part of data which larger than 15000
                self.send_buffer = self.send_buffer[15000:]
            else:
                new_packet = DataPacket()
                new_packet.seq = self.next_seq_send
                new_packet.data = bytes(self.send_buffer[0:len(self.send_buffer)])
                new_packet.hash = 0
                new_packet.hash = binascii.crc32(new_packet.__serialize__()) & 0xffffffff
                # set the send_buffer to be empty again
                self.send_buffer = []

            #
            if self.next_seq_recv == 2 ** 32:
                self.next_seq_recv = 0

            else:
                self.next_seq_send = self.next_seq_send + 1

            resend_packet = ResendPacket()
            resend_packet.seq = new_packet.seq
            resend_packet.data = new_packet.data
            resend_packet.hash = new_packet.hash
            resend_packet.TIMESTAMP = time.time()
            self.send_window.append(resend_packet)
            self.transport.write(new_packet.__serialize__())

    async def resend_check(self):
        while True:
            current_time = time.time()
            for resend_packet in self.send_window_:
                if current_time - resend_packet.TIMESTAMP > 2:
                    packet = DataPacket()
                    packet.seq = resend_packet.seq
                    packet.data = resend_packet.data
                    packet.hash = resend_packet.hash
                    self.transport.write(packet.__serialize__())
                    resend_packet.TIMESTAMP = current_time
            await asyncio.sleep(0.5)

    def datapacket_recv(self, packet):
        self.last_data_time = time.time()
        # Drop if not a datapacket
        if packet.DEFINITION_IDENTIFIER != "poop.datapacket":
            logger.debug("Not the expected data packet. Dropped!")
            return

        # If ACK is set, handle ACK
        if packet.ACK:
            # Check hash, drop if invalid
            tmp_packet = DataPacket()
            tmp_packet.ACK = packet.ack
            tmp_packet.hash = 0
            if binascii.crc32(tmp_packet.__serialize__()) & 0xffffffff != packet.hash:
                logger.debug("The hash doesn't match. Dropped!")
                return
            # If ACK matches sequence of a packet in send queue, take off of send queue, and update send queue
            self.send_window[:] = [send_pkt for send_pkt in self.send_window if send_pkt.seq != packet.ack]

            if self.send_window:
                self.next_expected_ack = self.send_window[0].seq
            else:
                self.next_expected_ack = packet.ACK + 1
            self.send_packets_inqueue()
            return
        # if there is no ack, which means the packets are data packets just received
        elif packet.seq <= self.next_seq_recv + self.recv_window_size:
            tmp_packet = DataPacket()
            tmp_packet.seq = packet.seq
            tmp_packet.data = packet.data
            tmp_packet.hash = 0
            if binascii.crc32(tmp_packet.__serialize__()) & 0xffffffff != packet.hash:
                logger.debug("The hash doesn't match. Dropped!")
                return
        else:
            logger.debug("The received sequence number doesn't in the range. Dropped!")
            return
        # continue the following when hash matches, send the sequence number of the already acquired packets
        new_ack_packet = DataPacket()
        new_ack_packet.ACK = packet.seq
        new_ack_packet.hash = 0
        new_ack_packet.hash = binascii.crc32(new_ack_packet.__serialize__()) & 0xffffffff
        self.transport.write(new_ack_packet.__serialize__())

        # add the coming packet into the window and sort
        self.recv_window.append(packet)
        self.recv_window.sort(key=lambda packet_: packet_.seq)

        # send the received packets to the higher application layer
        while self.recv_window:
            if self.recv_window[0].seq == self.next_seq_recv:
                self.higherProtocol().data_received(self.recv_window.pop(0).data)
                # while self.recv_window:
                #     if self.recv_window[0].seq == self.next_seq_recv:
                #         self.recv_window.pop(0)
                #     else:
                #         break
                # when the received sequence number is outer bound, reset to 0
                if self.next_seq_recv == 2 ** 32:
                    self.next_seq_recv = 0
                else:
                    self.next_seq_recv = self.next_seq_recv + 1
            else:
                logger.debug("There may be error??")
                break

    # --------------------------------------------------------------------------------------------------------
    def shut(self):
        self.send_shutdown_packet()

    def send_shutdown_packet(self):
        new_shut_packet = self.transport.write()
        new_shut_packet.FIN = self.next_seq_recv
        self.transport.write(new_shut_packet.__serialize__())
        self.shutdown_time = time.time()
        self.loop.create_task(self.check_shutdown_timeout())
        self.status = 'FIN_SENT'
        return

    async def check_shutdown_timeout(self):
        while True:
            if self.check_shutdown_count < 2:
                if (time.time() - self.shutdown_time) > 5:
                    self.send_shutdown_packet()
                    self.check_shutdown_count = self.check_shutdown_count + 1
            else:
                logger.debug("Shut down time outer bound!")
                self.transport.close()
            await asyncio.sleep(5 - (time.time() - self.shutdown_time))

    def shutdown_recv(self, packet):
        if not packet.FIN:
            return
        if packet.FIN == self.next_seq_recv:
            Fack_packet = ShutdownPacket()
            Fack_packet.Fack = packet.FIN
            self.transport.write(Fack_packet.__serialize__())
            self.transport.close()


# from playground.network.common import StackingProtocolFactory
#
# PassthroughFactory = StackingProtocolFactory.CreateFactoryType(PassthroughProtocol)
# factory1 = PassthroughFactory()

PassthroughClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOPProtocol(mode="client")
)

PassthroughServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOPProtocol(mode="server")
)

