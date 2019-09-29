'''
Created on Mar 18, 2014

@author: sethjn
'''

import sys
sys.path.append("../..")

import time, random, os
import getpass

from Exchange import BitPoint
from PermanentObject import PermanentObjectMixin
from CipherUtil import RSA_SIGNATURE_MAC, loadCertFromFile, loadPrivateKeyFromPemFile, getCertSubject


class BitPointVerifier(object):
    SIG_ALGO = RSA_SIGNATURE_MAC
    
    def __init__(self, authorityCert):
        self.__issuer = getCertSubject(authorityCert)["commonName"]
        publicKey = authorityCert.public_key()
        self.__verifier = self.SIG_ALGO(publicKey)
        
    def verify(self, bp):
        sigVerified = self.__verifier.verify(bp.mainDataBlob(), bp.signatureBlob())
        if not sigVerified:
            return (False,"Invalid signature")
        if bp.issuer() != bytes(self.__issuer,"utf-8"):
            return (False, "Invalid issuer %s (expected %s)" % (bp.issuer(), self.__issuer))
        return (True,"Validated Correctly")

class PrintingPress(PermanentObjectMixin):
    INSTANCE = None
    #ISSUER = "PLAYGROUND PROJECT ROOT BANK - Q1 2014"
    
    SERIES_RANGE = 9999999999
    
    """PASSWORD_SALT = "PRINTING_PRESS"
    ENCRYPTION_IV = "PENNYSAVEDEARNED"
    SIGNATURE_SIZE = 128"""
    
    @classmethod
    def CreateBankVault(cls, filename, certificate, privateKey, password, startingSerialNumber=0):
        seriesStringLength = len(str(cls.SERIES_RANGE))
        seriesTemplate = "P%" + ("%0d"%seriesStringLength) + "d"
        series = seriesTemplate % random.randint(0,cls.SERIES_RANGE)
        cls.secureSaveState(filename, certificate, privateKey, password, serialNumber=startingSerialNumber, series=series)
    
    def __init__(self, certificate, password, bankStateVaultFileName):
        if not os.path.exists(bankStateVaultFileName):
            raise Exception ("No Bank State Vault %s" % bankStateVaultFileName)
        if PrintingPress.INSTANCE:
            raise Exception("Duplicate Printing Press")
        PrintingPress.INSTANCE = self
        self.__cert = certificate
        self.ISSUER = getCertSubject(self.__cert)["commonName"]
        self.__password = password
        self.__stateFileName = bankStateVaultFileName
        self.__loadState()
        
    def __loadState(self):
        self.__privateKey, state = self.secureLoadState(self.__stateFileName, self.__cert, self.__password)
        self.__signaturePad = RSA_SIGNATURE_MAC(self.__privateKey)
        self.__serialNumber = state["serialNumber"]
        self.__series = state["series"]
        
    def __saveState(self):
        self.CreateBankVault(self.__stateFileName, self.__cert, self.__privateKey, self.__password, self.__serialNumber)
        
    def __getNewSerialNumbers(self, count=1):
        baseSerialNumber = self.__serialNumber
        self.__serialNumber += count
        self.__saveState()
        return [baseSerialNumber+i for i in range(count)]
    
    def mintBitPoints(self, count, depositor):
        newSerialNumbers = self.__getNewSerialNumbers(count)
        bitPoints = []
        for i in range(count):
            bitPoint = BitPoint.mintNew(
                issuer=self.ISSUER,
                serialNumber="%020d" % newSerialNumbers[i],
                timestamp=time.ctime()
            )
            bitPointBin = bitPoint.mainDataBlob()
            bitPoint.setSignature(self.__signaturePad.sign(bitPointBin))
            bitPoints.append(bitPoint)
            
        depositor(bitPoints)
    
def test_start(filename, cert, key, passwd, depositor):
    PrintingPress.CreateBankVault(filename, cert, key, passwd)
    mint = PrintingPress(cert, passwd, filename)
    mint.mintBitPoints(10, depositor)
    mint.mintBitPoints(20, depositor)
    
def simulate_shutdown():
    PrintingPress.INSTANCE = None
    
def test_reload(filename, cert, passwd, depositor):
    mint = PrintingPress(cert, passwd, filename)
    mint.mintBitPoints(10, depositor)
    
def test_basic():
    
    def printPoints(p):
        for bp in p:
            print(bp)
    
    filename, cert, key = sys.argv[1:]
    cert = loadCertFromFile(cert)
    key = loadPrivateKeyFromPemFile(key)
    passwd = getpass.getpass()
    
    test_start(filename, cert, key, passwd, printPoints)
    simulate_shutdown()
    test_reload(filename, cert, passwd, printPoints)

class DefaultSerializer(object):
    def __init__(self, outputDir=None, filebase="bitpoints"):
        self.__outputDir = outputDir
        if outputDir and not os.path.exists(self.__outputDir):
            raise Exception("No such directory %s" % self.__outputDir)
        self.__base = filebase  
        
    def __call__(self, bps):
        filename = "%s.%d.%s" % (self.__base, len(bps), time.ctime().replace(" ","_").replace(":","_"))
        if self.__outputDir:
            filename = os.path.join(self.__outputDir, filename)
        while os.path.exists(filename):
            filename = filename + "_{}".format(random.randint(0,9))
        with open(filename, "wb+") as f:
            for s in bps:
                f.write(s.serialize())
    
def main(args):
    if args[0] == "create":
        cert, key, filename = args[1:4]
        cert = loadCertFromFile(cert)
        key = loadPrivateKeyFromPemFile(key)
        passwd = getpass.getpass("Create mint password: ")
        passwd2 = getpass.getpass("Re-enter mint password: ")
        if passwd != passwd2:
            sys.exit("Passwords do not match")
        PrintingPress.CreateBankVault(filename, cert, key, passwd)
    elif args[0] == "mint":
        if len(args) == 1 or args[1].lower() in ["--help", "-h", "help"]:
            sys.exit("mint <amount> <cert> <filename> [<output_dir>]\n"+
                     "  amount can be of the form <amount>:<denomination>")
        amount, cert, filename = args[1:4]
        if len(args) > 4:
            outputDir = args[4]
        else:
            outputDir = None
        cert = loadCertFromFile(cert)
        if ":" in amount:
            amount, denominations = amount.split(":")
        else:
            denominations = amount
        amount = int(amount)
        denominations = int(denominations)
        passwd = getpass.getpass("Mint password: ")
        total = 0
        serializer = DefaultSerializer(outputDir)
        mint = PrintingPress(cert, passwd, filename)
        while total < amount:
            print("Minting %d of %d bitpoints" % ((total+denominations),amount))
            mint.mintBitPoints(denominations, serializer)
            total += denominations
    elif args[0] == "info":
        filename = args[1]
        if len(args) > 2:
            sampleSize = args[2]
        else:
            sampleSize = None
        bitpoints = []
        with open(filename,"rb") as f:
            bitpoints = BitPoint.deserializeAll(f)
        print("Deserialized",len(bitpoints),"bitpoints")
        if sampleSize == None:
            sample = []
        elif sampleSize.lower() == "all":
            sample = bitpoints
        else:
            start,stop = sampleSize.split(":")
            start = int(start.strip())
            stop = int(stop.strip())
            sample = bitpoints[start:stop]
        for bp in sample:
            print(bp)
    elif args[0] == "validate":
        filename, issuingCert = args[1:3]
        bitpoints = []
        with open(filename,"rb") as f:
            bitpoints = BitPoint.deserializeAll(f)
        cert = loadCertFromFile(issuingCert)
        verifier = BitPointVerifier(cert)
        numValid = 0
        for bp in bitpoints:
            isValid, reason = verifier.verify(bp)
            if isValid:
                numValid += 1
            else:
                print(bp.serialNumber(),"is NOT valid:", reason)
        print("Valid bitpoints: %s/%s" % (numValid, len(bitpoints)))

if __name__ == "__main__":
    main(sys.argv[1:])