from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
from ..poop.protocol import POOP
import logging
import time
import asyncio
import random
from random import randrange
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER, LIST
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

#-------------------------------------------------------------------try to get root cert
RootcertPath = "~/.playground/connectors/crapTS/20194_root.cert"
Team4CertPath = "~/.playground/connectors/crapTS/csr_team4_signed.cert"
Team4PrivateKeyPath = "~/.playground/connectors/crapTS/key_team4.pem"

def loadFile(path):
    with open(path, "r") as key_file:
        return key_file.read().encode("ASCII")



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
                ("cert", BUFFER({Optional:True})),
                ("certChain", LIST(BUFFER, {Optional:True}))
           ]

class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("data", BUFFER),
        ("signature", BUFFER),
    ]

class ErrorPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.errorpacket”"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("message", STRING),
    ]

class ErrorHandleClass():
    def handleException(self, e):
        print(e)

class SecureTransport(StackingTransport):
    def connect_protocol(self, protocol):
        self.protocol= protocol


class CRAP(StackingProtocol):
    def __init__(self, mode):
        logger.debug("{} CRAP: craptography protocol".format(mode))
        print("Verfying.......")
        self.mode = mode
        self.pk = None
        self.signature = None
        self.cert = None
        self.certChain = None
        self.higher_transport = None
        self.deserializer = CrapPacketType.Deserializer(errHandler=ErrorHandleClass())

    def connection_made(self, transport):
        logger.debug("{} CRAP: connection made".format(self.mode))
        #self.loop = asyncio.get_event_loop()
        self.last_recv = time.time()
        self.transport = transport
        self.higher_transport = SecureTransport(transport)
        self.higher_transport.connect_protocol(self)
        #self.loop.creat_task(self.connection_timeout_check())

        #There are some codes about create the cert


        #There are some codes about sign the public key

        if self.mode == "client":
            print("connecton made")
            #generate RSA signKA and public key
            self.l_private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,
                backend=default_backend())
            self.l_public_key = self.l_private_key.public_key()

            rootcert = x509.load_pem_x509_certificate(loadFile(RootcertPath), default_backend())
            team4cert = x509.load_pem_x509_certificate(loadFile(Team4CertPath), default_backend())
            self.t4privatek = serialization.load_pem_private_key(loadFile(Team4PrivateKeyPath),password=b'passphrase', backend=default_backend())


            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"20194.4.0.25"),])     #I hava already change the common name
            
            # I think this is the place to sign the cert
            # And the other problem is how to use AESGCM to authenticated encryption
            certA = x509.CertificateBuilder().subject_name(subject).issuer_name(
                issuer).public_key(
                    self.l_public_key).serial_number(x509.random_serial_number()
                        ).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(
                            x509.SubjectAlternativeName([x509.DNSName(u"20194.4.0.25")]),critical=False,).sign(self.t4privatek, hashes.SHA256(), default_backend())
            certA_bytes = certA.public_bytes(Encoding.PEM)
            print("certA_bytes: fan zheng you dongxi")    
            publickey_bytesA = self.l_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


            #self.nonceA = os.urandom(32)
            self.nonceA = random.randrange(0, 10000)
            self.privatekA = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.pk = self.privatekA.public_key()
            self.pk_bytes = self.pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            self.signature = self.l_private_key.sign(
                self.pk_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()
            )       #Get signature
            #This cert is nothing
            print("client's self.pk_bytes")
            print("client's self.signature")
            handshake_pkt = HandshakePacket(status = 0, nonce = self.nonceA, pk = self.pk_bytes, 
                signature = self.signature, cert = certA_bytes, certChain = self.certChain)
            print("client packet already generate a packet")

            self.certChain = [loadFile(Team4CertPath)]

            self.transport.write(handshake_pkt.__serialize__())
            print("client already sent")
            #self.handshake_timeout_task = self.loop.create_task(self.handshake_timeout_check())
    
    def handshake_send_error(self):
        print("handshake error!")
        error_pkt = HandshakePacket(status=2)
        self.transport.write(error_pkt.__serialize__())
        return
    
    def data_received(self, buffer):
        print("received data!@!")
        self.deserializer.update(buffer)
        for packet in self.deserializer.nextPackets():
            if isinstance(packet, HandshakePacket) and self.handshake:
                self.handshake_pkt_recv(packet)
            elif isinstance(packet, DataPacket) and not self.handshake:
                self.data_pkt_recv(packet)
            elif isinstance(packet, ErrorPacket):
                print ("ERROR: Wrong packet!!!!!")


    def handshake_pkt_recv(self, pkt):
        print("first recive a data")
        if self.mode == "server":
            if pkt.status == 2:
                logger.debug("{}, CRAP: ERROR: recv an error packet ".format(self.mode))
                return
            elif pkt.status == 0:
                print("LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL")
                # We need to transfer bytes in to object
                print("get packet")

                #get certificate
                rootcert = x509.load_pem_x509_certificate(loadFile(RootcertPath), default_backend())
                team4cert = x509.load_pem_x509_certificate(loadFile(Team4CertPath), default_backend())
                Acert = x509.load_pem_x509_certificate(pkt.cert, default_backend())

                spublic_keyA = Acert.public_key()
                print("Server get cert from client:")
                print(Acert)
                try:
                    print("begin verify client's signature")
                    spublic_keyA.verify(
                        pkt.signature,
                        pkt.pk,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                    print("verify client's signature success!!!!")
                except Exception as error:
                    logger.debug("Wrong signature from client!!!!!!!")
                    handshake_pkt = HandshakePacket(status=2)
                    self.transport.write(handshake_pkt.__serialize__())
                    self.transport.close()

                #-----------------------------------------verify transported cert
                for certdata in pkt.certChain:
                    cert = x509.load_pem_x509_certificate(certdata, default_backend())
                    print("Begin verify certificate in cert chain")
                    team_address = cert.subject.get_attributes_for_aid(NameOID.COMMON_NAME)[0].value
                    receive_address = Acert.subject.get_attributes_for_aid(NameOID.COMMON_NAME)[0].value
                    if team_address == receive_address:
                        pass
                    else:
                        logger.debug("Invalid certificate from server!!!!!!!")
                        handshake_pkt = HandshakePacket(status=2)
                        self.transport.write(handshake_pkt.__serialize__())
                        self.transport.close()
                
                self.privatekB = ec.generate_private_key(ec.SECP384R1(), default_backend())
                self.pk = self.privatekB.public_key()

                self.l_private_keyB = rsa.generate_private_key(public_exponent=65537,key_size=2048,
                    backend=default_backend())
                self.l_public_keyB = self.l_private_keyB.public_key()

                self.t4privatek = serialization.load_pem_private_key(loadFile(Team4PrivateKeyPath),password=b'passphrase',backend=default_backend())
                subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
                    x509.NameAttribute(NameOID.COMMON_NAME, u"20194.4.0.26"),])   #This common name has also been changed
                certB = x509.CertificateBuilder().subject_name(subject).issuer_name(
                    issuer).public_key(
                        self.l_public_keyB).serial_number(x509.random_serial_number()
                            ).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(
                                x509.SubjectAlternativeName([x509.DNSName(u"20194.4.0.26")]),critical=False,).sign(self.t4privatek, hashes.SHA256(), default_backend())
                certB_bytes = certB.public_bytes(Encoding.PEM)

                self.nonceB = random.randrange(0, 2**10)    #os.urandom(32)
                nonceSignatureB = self.l_private_keyB.sign(
                    str(pkt.nonce).encode('ASCII'),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()
                )

                self.certChain = [loadFile(Team4CertPath)]
                self.pk_bytes = self.pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                self.signature = self.l_private_keyB.sign(
                    self.pk_bytes,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()
                )       #Get signature
                self.cert = certB_bytes
                handshake_pkt = HandshakePacket(pk = self.pk_bytes, status = 1, nonce = self.nonceB, 
                    nonceSignature=nonceSignatureB,
                    signature = self.signature, cert = self.cert, certChain = self.certChain)    # This is peer2 first get packet
                self.transport.write(handshake_pkt.__serialize__())

                # publickeyA = load_pem_public_key(pkt.pk, backend=default_backend())
                # server_shared_key = self.privatekB.exchange(ec.ECDH, publickeyA)#Alreday calcualte
                # print("Calculate the server_shared_key success!!!")
            elif pkt.status == 1:
                try:
                    print("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
                    spublic_keyA.verify(pkt.nonceSignature, str(self.nonceB).encode('ASCII'),
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256())
                    print("Server verify nonceB success!!!!!")
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
            
        elif self.mode == "client" and pkt.status == 1:
            #peer1 or peer2 has sent his public key and try to first verify cert and second calculate the shared key
            #There are some codes about verify the cert 
            if pkt.status == 1:     #peer1 first get the public key from peer2

                
                Bcert = x509.load_pem_x509_certificate(pkt.cert, default_backend())
                spublic_keyB = Bcert.public_key()
                try:
                    print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
                    spublic_keyB.verify(pkt.signature, pkt.pk,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256())
                    print("verify public key success!")
                    spublic_keyB.verify(pkt.nonceSignature, str(self.nonceA).encode('ASCII'),
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256())
                    print("verify nonce success!")

                except Exception as error:
                    logger.debug("Sever verify failed because wrong signature")
                    handshake_pkt = HandshakePacket(status=2)
                    self.transport.write(handshake_pkt.__serialize__())
                    self.transport.close()     

                for certdata in pkt.certChain:
                    cert = x509.load_pem_x509_certificate(certdata, default_backend())
                    print("Begin verify certificate in cert chain")
                    team_address = cert.subject.get_attributes_for_aid(NameOID.COMMON_NAME)[0].value
                    receive_address = Bcert.subject.get_attributes_for_aid(NameOID.COMMON_NAME)[0].value
                    if team_address == receive_address:
                        pass
                    else:
                        logger.debug("Invalid certificate from server!!!!!!!")
                        handshake_pkt = HandshakePacket(status=2)
                        self.transport.write(handshake_pkt.__serialize__())
                        self.transport.close()
          
                    
                print("begin to send next packe")
                # publickeyB = load_pem_public_key(pkt.pk, backend=default_backend())
                # print("publickeyB:", publickeyB)
                # client_shared_key = self.privatekA.exchange(ec.ECDH, publickeyB)
                # print("client_shared_key:", client_shared_key)
                nonceSignatureA = self.l_private_key.sign(str(pkt.nonce).encode('ASCII'),
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                                     hashes.SHA256())
                print(nonceSignatureA)
                handshake_pkt = HandshakePacket(status=1, nonceSignature=nonceSignatureA)
                print("-------------send packet second time!!!------------------")
                self.transport.write(handshake_pkt.__serialize__())
            else:
                self.handshake_send_error()
                return
    
SecureClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOP(mode="client"), lambda: CRAP(mode="client"))

SecureServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOP(mode="server"), lambda: CRAP(mode="server"))
