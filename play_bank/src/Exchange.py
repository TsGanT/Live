'''
Created on Mar 18, 2014

@author: sethjn
'''

import struct


def dumpString(s):
    return struct.pack("!H%ds" % len(s), len(s), s)


def restoreString(data, offset=0):
    size = struct.unpack_from("!H", data, offset)[0]
    s = struct.unpack_from("!%ds" % size, data, offset+struct.calcsize("!H"))[0]
    return s


def calcsizeNextString(data, offset=0):
    size = struct.unpack_from("!H", data, offset)[0]
    return struct.calcsize("!H%ds" % size)


def dumpStrings(ss):
    output = b""
    for s in ss:
        stringDump = dumpString(bytes(s,"utf-8"))
        output += stringDump
    return output


class BitPoint(object):
    @classmethod
    def mintNew(cls, issuer, serialNumber, timestamp):
        bp = BitPoint()
        bp.__issuer = issuer
        bp.__serialNumber = serialNumber
        bp.__timestamp = timestamp
        bp.__mainData = dumpStrings([issuer, serialNumber, timestamp])
        bp.__signature = ""
        bp.__signatureData = ""
        return bp
        
    @classmethod
    def deserialize(cls, blob):
        bp = BitPoint()
        offset = 0
        bp.__issuer = restoreString(blob, offset)
        offset += calcsizeNextString(blob, offset)
        bp.__serialNumber = restoreString(blob, offset)
        offset += calcsizeNextString(blob, offset)
        bp.__timestamp = restoreString(blob, offset)
        offset += calcsizeNextString(blob, offset)
        bp.__mainData = blob[:offset]
        bp.__signature = restoreString(blob, offset)
        sigStartOffset = offset
        offset += calcsizeNextString(blob, offset)
        bp.__signatureData = blob[sigStartOffset:offset]
        
        return (bp, offset)
    
    @classmethod
    def deserializeAll(cls, f):
        bpData = f.read(2048)
        bps=[]
        while bpData:
            newBitPoint, offset = BitPoint.deserialize(bpData)
            bpData = bpData[offset:]
            if len(bpData) < 1024:
                bpData += f.read(2048)
            bps.append(newBitPoint)
        return bps
    
    def __init__(self):
        self.__issuer = None
        self.__serialNumber = None
        self.__timestamp = None
        self.__mainData = None
        self.__signature = None
        
    def serialNumber(self): return self.__serialNumber
    def issuer(self): return self.__issuer
    def timestamp(self): return self.__timestamp
    
    def serialize(self): return self.__mainData + self.__signatureData
    def serializeInto(self, f): f.write(self.serialize())
    def mainDataBlob(self): return self.__mainData
    def signatureBlob(self): return self.__signature

    def setSignature(self, signature):
        if self.__signature != "":
            raise Exception("Attempting to change the signature on a minted BitPoint!")
        self.__signature = signature
        self.__signatureData = dumpString(signature)
    
    def __str__(self):
        return "BitPoint: %s (Issued %s by %s)" % (self.__serialNumber, self.__timestamp, self.__issuer)


class BitPointCredit(object):
    def __init__(self):
        pass
