from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
import time
import asyncio
from random import randrange
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional

import binascii
import bisect

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat

from OpenSSL.crypto import load_privatekey, FILETYPE_PEM, sign
import base64

logger = logging.getLogger("playground.__connector__." + __name__)

class CrapPacketType(PacketType):
    DEFINITION_IDENTIFIER = "crap"
    DEFINITION_VERSION = "1.0"

class HandshakePacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.handshakepacket"
    DEFINITION_VERSION = "1.0"
    NOT_STARTED = 0
    SUCCESS     = 1
    ERROR       = 2
    FIELDS = [
        ("status", UINT8),
        ("signature", BUFFER({Optional:True})),
        ("pk", BUFFER({Optional:True})),
        ("cert", BUFFER({Optional:True}))
    ]

class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("data", BUFFER),
        ("signature", BUFFER),
    ]

class ErrorHandleClass():
    def handleException(self, e):
        print(e)


class CRAP(StackingProtocol):
    def __init__(self, mode):
        logger.debug("{} CRAP: craptography protocol".format(mode))
        print("Verfying.......")
        self._mode = mode
        self.status = 0
        self.l_private_key = None
        self.pk = None
        self.pk_bytes = None
        self.shared_key = None
        self.signature = None
        self.cert = None
        self.last_recv = 0      #time of last packet received, in case for a long time
        self.shutdown_wait_start = 0
        self.privatek = None
        self.deserializer = CrapPacketType.Deserializer(errHandler=ErrorHandleClass())

    def tsl_connection_made(self, transport):
        logger.debug("{} CRAP: connection made".format(self._mode))
        self.loop = asyncio.get_event_loop()
        self.last_recv = time.time()
        self.loop.creat_task(self.connection_timeout_check())
        self.l_private_key = load_privatekey(FILETYPE_PEM, open("private.pem").read())

        #There are some codes about create the cert


        #There are some codes about sign the public key

        self.status = "LISTEN"

        if self._mode == "peer1":
            self.privatek = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.pk = self.privatek.public_key()
            self.pk_bytes = self.pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            self.signature = sign(self.l_private_key, self.pk_bytes, 'SHA256')
            self.cert = base64.b64encode(self.signature)        #I am not ure if this is correct?
            handshake_pkt = HandshakePacket(status = 0, pk = self.pk, signature = self.signature, cert = self.cert)
            self.transport.write(handshake_pkt.__serialize__())

            self.handshake_timeout_task = self.loop.create_task(self.handshake_timeout_check())
            self.status = "PK_SENT"
    
    def handshake_send_error(self):
        print("handshake error!")
        error_pkt = HandshakePacket(status=2)
        self.transport.write(error_pkt.__serialize__())
        return
    
    def printpkt(self, pkt):  # try to print packet content
        print("-----------")
        for f in pkt.FIELDS:
            fname = f[0]
            print(fname + ": " + pkt._fields[fname]._data)
        print("-----------")
        return
    
    def handshake_pkt_recv(self, pkt):
        if pkt.status == 2:
            logger.debug("{}, CRAP: ERROR: recv an error packet ".format(self._mode))
            return
        elif self.status == "LISTEN":
            if pkt.status == 0:
                if pkt.pk:
                    if base64.b64decode(pkt.cert) == pkt.signature:
                        self.privatek = ec.generate_private_key(ec.SECP384R1(), default_backend())
                        self.pk = self.privatek.public_key()
                        self.pk_bytes = self.pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                        self.signature = sign(self.l_private_key, self.pk_bytes, 'SHA256')
                        self.cert = base64.b64encode(self.signature)
                        handshake_pkt = HandshakePacket(pk = self.pk, status = 1, 
                            signature = self.signature, cert = self.cert)    # This is peer2 first get packet
                        self.transport.write(handshake_pkt.__serialize__())
                        self.shared_key = self.privatek.exchange(ec.ECDH(), pkt.pk)     #Alreday calcualte
                        self.status = "PK_SENT"
                else:
                    # ERROR: there is no public key in the packet
                    self.handshake_send_error()
                    return
            else:
                #ERROR: This is peer2 and the first time the status cannot be 1 or 2
                self.handshake_send_error()
                return
            
        elif self.status == "PK_SENT":
            #peer1 or peer2 has sent his public key and try to first verify cert and second calculate the shared key
            #There are some codes about verify the cert 

            if pkt.status == 1:     #peer1 first get the public key from peer2
                if base64.b64decode(pkt.cert) == pkt.signature:
                    if pkt.pk:  #There is public key in the package
                        if self._mode == "peer1":
                            self.shared_key = self.privatek.exchange(ec.ECDH(), pkt.pk)
                        self.status = "ESTABLISHED"
                        # self.last_recv = time.time()
                        # self.loop.create_task(self.wait_datapkt_timeout())
                        #if we will wait for next data packet, we need this codes
                    else:
                        self.handshake_send_error()
                        return
            

    async def connection_timeout_check(self):
        while True:
            if (time.time() - self.last_recv) > 300:
                # time out after 5 min
                print("Shutdown due to: connection timeout")
                self.status = "DYING"
                self.higherProtocol().connection_lost(None)
                self.transport.close()
                return
            await asyncio.sleep(300 - (time.time() - self.last_recv))

    async def handshake_timeout_check(self):
        count = 0
        while count < 3:
            # if (time.time() - self.last_recv) > 1:
            # time out after 10 sec
            if self.status == "ESTABLISHED" or self.status == "FIN_SENT" or self.status == "DYING":
                return
            handshake_pkt = HandshakePacket(status=0)
            self.transport.write(handshake_pkt.__serialize__())
            count += 1
            await asyncio.sleep(1)
    
PassthroughClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: CRAP(mode="peer1"))

PassthroughServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: CRAP(mode="peer2"))