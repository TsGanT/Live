from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
from ..poop.protocol import POOP
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
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat


from cryptography import x509
from cryptography.x509.oid import NameOID
#from OpenSSL.crypto import load_privatekey, FILETYPE_PEM, sign
import os      #used for generate random number and compare two nounce
import datetime

logger = logging.getLogger("playground.__connector__." + __name__)

#----------------------------------------------------------------This is crap protocol packet
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
            ("nonce", UINT32({Optional:True})),
            ("nonceSignature", BUFFER({Optional:True})),
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
        self.l_public_key = None
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
        #self.loop = asyncio.get_event_loop()
        self.last_recv = time.time()
        #self.loop.creat_task(self.connection_timeout_check())

        #There are some codes about create the cert


        #There are some codes about sign the public key

        self.status = "LISTEN"

        if self._mode == "client":
            #generate RSA signKA and public key
            self.l_private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,
                backend=default_backend())
            self.l_public_key = self.l_private_key.public_key()
            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),])
            certA = x509.CertificateBuilder().subject_name(subject).issuer_name(
                issuer).public_key(
                    self.l_public_key).serial_number(x509.random_serial_number()
                        ).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(
                            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),critical=False,).sign(self.l_private_key, hashes.SHA256(), default_backend())
            certA_bytes = certA.public_bytes(Encoding.PEM)

            # with open("kl_private_key.pem", "wb") as f:
            #     f.write(key.private_bytes(
            #         encoding=serialization.Encoding.PEM,
            #         format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
            #     ))    # in fact, we need to know how to get a cert
            
            publickey_bytesA = self.l_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


            self.nonceA = os.urandom(32)
            self.privatekA = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.pk = self.privatekA.public_key()
            self.pk_bytes = self.pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            self.signature = self.l_private_key.sign(
                self.pk_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()
            )       #Get signature
            #This cert is nothing
            handshake_pkt = HandshakePacket(status = 0, nonce = self.nonce, pk = self.pk_bytes, 
                signature = self.signature, cert = certA_bytes)
            self.transport.write(handshake_pkt.__serialize__())

            #self.handshake_timeout_task = self.loop.create_task(self.handshake_timeout_check())
            self.status = "PK_SENT"
    
    def handshake_send_error(self):
        print("handshake error!")
        error_pkt = HandshakePacket(status=2)
        self.transport.write(error_pkt.__serialize__())
        return
    
    
    def handshake_pkt_recv(self, pkt):
        if pkt.status == 2:
            logger.debug("{}, CRAP: ERROR: recv an error packet ".format(self._mode))
            return
        elif self.status == "LISTEN":
            if pkt.status == 0:
                # We need to transfer bytes in to object
                Acert = x509.load_pem_x509_certificate(pkt.cert, default_backend())

                try:
                    pkt.Acert.public_key().verify(
                        pkt.signature,
                        pkt.pk,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                except Exception as error:
                    logger.debug("Wrong signature from client!!!!!!!")
                    handshake_pkt = HandshakePacket(status=2)
                    self.transport.write(handshake_pkt.__serialize__())
                    self.transport.close()

                self.privatekB = ec.generate_private_key(ec.SECP384R1(), default_backend())
                self.pk = self.privatekB.public_key()

                self.l_private_keyB = rsa.generate_private_key(public_exponent=65537,key_size=2048,
                    backend=default_backend())
                self.l_public_keyB = self.l_private_keyB.public_key()
                subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
                    x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),])
                certB = x509.CertificateBuilder().subject_name(subject).issuer_name(
                    issuer).public_key(
                        self.l_public_keyB).serial_number(x509.random_serial_number()
                            ).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(
                                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),critical=False,).sign(self.l_private_keyB, hashes.SHA256(), default_backend())
                certB_bytes = certB.public_bytes(Encoding.PEM)

                self.nonceB = os.urandom(32)
                nonceSignatureB = self.l_private_keyB.sign(
                    pkt.nonce,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()
                )

                self.pk_bytes = self.pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                self.signature = self.l_private_keyB.sign(
                    self.pk_bytes,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()
                )       #Get signature
                self.cert = certB
                handshake_pkt = HandshakePacket(pk = self.pk_bytes, status = 1, nonce = self.nonceB, 
                    nonceSignature=nonceSignatureB,
                    signature = self.signature, cert = self.cert)    # This is peer2 first get packet
                self.transport.write(handshake_pkt.__serialize__())

                publickeyA = load_pem_public_key(pkt.pk, backend=default_backend())
                server_shared_key = self.privkB.exchange(ec.ECDH, publickeyA)#Alreday calcualte
                self.status = "PK_SENT"
            elif pkt.status == 1:
                try:
                    self.l_public_keyB.verify(pkt.nonceSignature, self.nonceB,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256())

                except Exception as error:
                    logger.debug("Sever verify failed because wrong signature")
                    handshake_pkt = HandshakePacket(status=2)
                    self.transport.write(handshake_pkt.__serialize__())
                    self.transport.close()
                print("Handshake complete")
                
            else:
                #ERROR: This is peer2 and the first time the status cannot be 1 or 2
                self.handshake_send_error()
                return
            
        elif self.status == "PK_SENT":
            #peer1 or peer2 has sent his public key and try to first verify cert and second calculate the shared key
            #There are some codes about verify the cert 

            if pkt.status == 1:     #peer1 first get the public key from peer2
                Bcert = x509.load_pem_x509_certificate(pkt.cert, default_backend())
                try:
                    pkt.cert.public_key().verify(pkt.signature, pkt.pk,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256())
                    pkt.cert.public_key().verify(pkt.nonceSignature, self.nonceA,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256())

                except Exception as error:
                    logger.debug("Sever verify failed because wrong signature")
                    handshake_pkt = HandshakePacket(status=2)
                    self.transport.write(handshake_pkt.__serialize__())
                    self.transport.close()               
            
                publickeyB = load_pem_public_key(pkt.pk, backend=default_backend())
                client_shared_key = self.privatekA.exchange(ec.ECDH, publickeyB)
                nonceSignatureA = self.signkA.sign(pkt.nonce,
                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                                    hashes.SHA256())

                handshake_pkt = HandshakePacket(status=1, nonceSignature=nonceSignatureA)
                self.transport.write(handshake_pkt.__serialize__())
            else:
                self.handshake_send_error()
                return
    
PassthroughClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: CRAP(mode="peer1"))

PassthroughServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: CRAP(mode="peer2"))