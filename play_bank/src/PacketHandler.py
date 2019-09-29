'''
Created on Nov 25, 2013

@author: sethjn
'''
from playground.network.packet import PacketType
import traceback, time

import logging
logger = logging.getLogger(__name__)


class DuplicateClientPacketHandler(Exception):
    def __init__(self, packetType):
        Exception.__init__(self, "Received a duplicate handler for packets of type %s" % packetType.DEFINITION_IDENTIFIER)


class InvalidArgumentException(Exception):
    """
    Common error for an unexpected argument to a Playground routine.
    Python has no invalid argument exception.
    """
    pass


class PacketHandlerFailure(Exception):
    """
    Error for a handler unexpectedly failing to handle a packet of
    the registered type.
    """
    pass


class PacketHandlerInterface(object):
    """
    Interface class for PLAYGROUND packet handling. The basic
    idea is to register a different handler for each type of
    packet received by a PLAYGROUND protocol.
    """
    def registerPacketHandler(self, packetType, handler):
        """
        Abstract method for registering a handler to a packetType.
        """
        pass

    def unregisterPacketHandler(self, packetType):
        """
        Abstract method for unregistering a handler to a packetType.
        """
        pass

    def handlePacket(self, protocol, pkt):
        """
        Abstract method for handling a packet. Note that the
        receiving protocol is passed so that the handler has access
        to the return channel (i.e., protocol.transport)
        
        This method returns True if a handler was found for
        the packet and False otherwise
        """
        return False


class SimplePacketHandler(PacketHandlerInterface):
    '''
    SimplePacketHandler is a straight-forward impelementation of the
    PacketHandlerInterface and suitable for most implementing classes.
    '''

    def __init__(self, base_type=PacketType):
        self.__packetHandlers = {}
        self.__buffer = base_type.Deserializer()
        
    def registerPacketHandler(self, packetType, handler):
        if not issubclass(packetType, PacketType):
            raise InvalidArgumentException("Expected a PacketType")
        
        versionMajorString, versionMinorString = packetType.DEFINITION_VERSION.split(".")
        versionMajor = int(versionMajorString)
        versionMinor = int(versionMinorString)
        
        if packetType not in self.__packetHandlers:
            self.__packetHandlers[packetType] = {}
        if versionMajor not in self.__packetHandlers[packetType]:
            self.__packetHandlers[packetType][versionMajor] = {}
        if versionMinor in self.__packetHandlers:
            raise DuplicateClientPacketHandler(packetType)
        self.__packetHandlers[packetType][versionMajor][versionMinor] = handler
        
    def unregisterPacketHandler(self, packetType):
        if not issubclass(packetType, PacketType):
            raise InvalidArgumentException("Expected a PacketType")
        
        versionMajorString, versionMinorString = packetType.DEFINITION_VERSION.split(".")
        versionMajor = int(versionMajorString)
        versionMinor = int(versionMinorString)
        if packetType.DEFINITION_IDENTIFIER in self.__packetHandlers:
            if versionMajor in self.__packetHandlers[packetType.DEFINITION_IDENTIFIER]:
                if versionMinor in self.__packetHandlers[packetType.DEFINITION_IDENTIFIER][versionMajor]:
                    del self.__packetHandlers[packetType.DEFINITION_IDENTIFIER][versionMajor][versionMinor]
                if len(self.__packetHandlers[packetType.DEFINITION_IDENTIFIER][versionMajor]) == 0:
                    del self.__packetHandlers[packetType.DEFINITION_IDENTIFIER][versionMajor]
            if len(self.__packetHandlers[packetType.DEFINITION_IDENTIFIER]) == 0:
                del self.__packetHandlers[packetType.DEFINITION_IDENTIFIER]
                
    def handleData(self, protocol, data):
        # processes data into packets. 
        # returns an integer for the number of
        # packets processed.
        
        self.__buffer.update(data)
        processed = 0
        for packet in self.__buffer.nextPackets():
            if self.handlePacket(protocol, packet):
                processed += 1
        return processed
            
    def handlePacket(self, protocol, pkt):
        #pkt = PacketType.Deserialize(pkt)
        version = pkt.DEFINITION_VERSION
        versionMajorString, versionMinorString = version.split(".")
        versionMajor = int(versionMajorString)
        versionMinor = int(versionMinorString)
        
        pktHandlerVersions = self.__packetHandlers.get(pkt.__class__, None)
        if not pktHandlerVersions:
            return False
        
        pktHandlerSpecificVersions = pktHandlerVersions.get(versionMajor, None)
        if not pktHandlerSpecificVersions:
            return False
        
        handler = pktHandlerSpecificVersions.get(versionMinor, None)
        if not handler:
            otherVersions = pktHandlerSpecificVersions.keys()
            otherVersions.append(versionMinor)
            otherVersions.sort()
            myIndex = otherVersions.index(versionMinor)
            if myIndex < len(otherVersions)-1:
                nextHighestVersion = otherVersions[myIndex+1]
                handler = pktHandlerSpecificVersions[nextHighestVersion]
                if handler:
                    # TODO: Put log packet here about handling one version with another
                    pass
                
        if not handler:
            return False
        try:
            handler(protocol, pkt)
        except Exception as e:
            print(traceback.format_exc())
            raise PacketHandlerFailure("Handler %s failed to handle %s %s (%s)" % (handler, protocol, pkt, e))
        return True
