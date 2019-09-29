'''
Created on Apr 1, 2014

@author: sethjn
'''

import os, pickle, time, dbm, traceback
from PermanentObject import PermanentObjectMixin
from collections import OrderedDict
from PrintingPress import BitPointVerifier
from Exchange import BitPoint

from CipherUtil import *


class LedgerLine(object):
    def __init__(self, prevLedger):
        if prevLedger:
            self.__prevNumber = prevLedger.number()
            self.__number = self.__prevNumber+1
        else:
            self.__prevNumber = -1
            self.__number = 0
        self.__accounts = OrderedDict()
        self.__complete = False
        self.__transactionDate = None
        self.__transactionMemo = None
        self.__transactionAccounts = set([])
        if prevLedger:
            for account in prevLedger.accounts():
                prevBalance = prevLedger.__accounts[account][2]
                self.__accounts[account] = [prevBalance, 0, prevBalance]
    
    def receiptForm(self, account):
        cloned = LedgerLine(None)
        cloned.__prevNumber = self.__prevNumber
        cloned.__number = self.__number
        cloned.__complete = self.__complete
        if account in self.__transactionAccounts:
            cloned.__transactionDate = self.__transactionDate
            cloned.__transactionMemo = self.__transactionMemo
            cloned.__transactionAccounts = self.__transactionAccounts.copy()
            for transAccount in self.__transactionAccounts:
                if account == transAccount:
                    cloned.__accounts[transAccount] = self.__accounts[transAccount]
                else:
                    cloned.__accounts[transAccount] = [0, self.__accounts[transAccount][1], 0]
        else:
            cloned.__accounts[account] = self.__accounts[account]
        return cloned
    
    def number(self):
        return self.__number
    
    def complete(self):
        return self.__complete
    
    def accounts(self):
        return self.__accounts.keys()
    
    def partOfTransaction(self, accountKey):
        return self.__accounts[accountKey][1] != 0
    
    def getBalance(self, accountKey):
        if accountKey not in self.__accounts.keys(): return None
        return self.__accounts[accountKey][2]
    
    def getTransactionAmount(self, accountKey):
        if accountKey not in self.__accounts.keys(): return None
        return self.__accounts[accountKey][1]
    
    def memo(self, accountKey):
        if accountKey not in self.__accounts.keys(): return None
        return self.__transactionMemo
    
    def date(self, accountKey):
        if accountKey not in self.__accounts.keys(): return None
        return self.__transactionDate
        
    def addAccount(self, accountKey):
        if self.__complete:
            raise Exception("Cannot add accounts after a ledger line has been used.")
        # first number is previous balance, second number is change, third number is current balance
        self.__accounts[accountKey] = [0, 0, 0]
        
    def setTransaction(self, transactionDate, transactionMemo, *transactionTriples):
        if self.__complete:
            raise Exception("Cannot set transaction. Already set.")
        for fromAccount, toAccount, amount in transactionTriples:
            if fromAccount not in self.__accounts:
                raise Exception("No such 'from account'")
            if toAccount not in self.__accounts:
                raise Exception("No such 'to account'")
            if amount < 0:
                raise Exception("Cannot transfer a negative amount")
        for fromAccount, toAccount, amount in transactionTriples:
            self.__transactionAccounts.add(fromAccount)
            self.__transactionAccounts.add(toAccount)
            self.__accounts[fromAccount][1] = -amount
            self.__accounts[fromAccount][2] -= amount
            self.__accounts[toAccount] [1] = amount
            self.__accounts[toAccount][2] += amount
        self.__transactionDate = transactionDate
        self.__transactionMemo = transactionMemo
        self.__complete = True
        
    def toHumanReadableString(self, forAccount=None):
        toAccounts = []
        fromAccounts = []
        for account in self.__accounts.keys():
            amount = self.__accounts[account][1]
            if amount < 0: fromAccounts.append(account)
            elif amount > 0: toAccounts.append(account)
        if forAccount is not None and forAccount not in (fromAccounts + toAccounts):
            return "(Null)\n"
        str = "Transfer "
        for account in fromAccounts:
            str += "%d from %s " % (-1*self.getTransactionAmount(account), account)
        str += "and "
        for account in toAccounts:
            str += "%d to %s " % (self.getTransactionAmount(account), account)
        str += " on %s. " % self.__transactionDate
        str += "Memo: %s\n" % (self.__transactionMemo or None)
        if forAccount is not None:
            str += "  %s Balance: %d\n" % (forAccount, self.getBalance(forAccount))
        else:
            for account in (fromAccounts + toAccounts):
                str += "  %s Balance: %d\n" % (account, self.getBalance(account))
        return str


class LedgerOperationResult(object):
    def __init__(self, success, msg="", code=None, value=None):
        self.__success = success
        self.__msg = msg
        self.__code = code
        self.__value = value
        
    def succeeded(self): return self.__success

    def code(self): return self.__code
    
    def msg(self): return self.__msg
    
    def value(self): return self.__value


class LedgerOperationFailure(LedgerOperationResult):
    def __init__(self, msg, code=None):
        LedgerOperationResult.__init__(self, False, msg, code)


class LedgerOperationSuccess(LedgerOperationResult):
    def __init__(self, msg="", code=None, value=None):
        LedgerOperationResult.__init__(self, True, msg, code, value)


class SecureItemStorage(PermanentObjectMixin):
    CONTROL_FILE = "secure_storage.bin"
    DB_FILE = "secure_storage"
    
    @classmethod
    def getKey(cls, o):
        return str(id(o))
    
    @classmethod
    def serialize(cls, o):
        return pickle.dumps(o)
    
    @classmethod
    def deserialize(cls, s):
        return pickle.loads(s)
    
    @staticmethod
    def filehash(fObj, readSize=1024):
        s1 = SHA()
        data = fObj.read(readSize)
        while data:
            if isinstance(data, type("string")):
                s1.update(bytes(data,"utf-8"))
            else: # isinstance(data, type(b"bytes")):
                s1.update(data)
            data = fObj.read(readSize)
        return s1.digest()
    
    @classmethod
    def InitializeStorage(cls, path, cert, privateKey, password):
        if not os.path.exists(path):
            raise Exception("No such path %s" % path)
        abspath = os.path.join(path, cls.CONTROL_FILE)
        dbAbsPath = os.path.join(path, cls.DB_FILE)
        # we have to cut off the .db because it is auto appended
        print("path",dbAbsPath)
        db = dbm.open(dbAbsPath, "n")
        db.close()
        with open(dbAbsPath, "rb") as f:
            dbHash = cls.filehash(f)
        cls.secureSaveState(abspath, cert, privateKey, password, db_hash=dbHash)
        
    def __init__(self, path, cert, password):
        self.__path = os.path.abspath(path)
        self.__cert = cert
        self.__password = password
        self._load()
                
    def _load(self):
        abspath = os.path.join(self.__path, self.CONTROL_FILE)
        self.__privateKey, state = self.secureLoadState(abspath, self.__cert, self.__password)
        dbAbsPath = os.path.join(self.__path, self.DB_FILE)
        with open(dbAbsPath, "rb") as f:
            dbHash = self.filehash(f)
        expectedDbHash = state["db_hash"]
        if expectedDbHash != dbHash:
            raise Exception("Database has changed since last access")
        self._db = dbm.open(dbAbsPath, "w")
        self._commitAddRequired = {}
        self._commitRemoveRequired = set([])
        
    def _save(self):
        abspath = os.path.join(self.__path, self.CONTROL_FILE)
        self._db.close()
        dbAbsPath = os.path.join(self.__path, self.DB_FILE)
        with open(dbAbsPath, "rb") as f:
            dbHash = self.filehash(f)
        self.secureSaveState(abspath, self.__cert, self.__privateKey, self.__password, db_hash=dbHash)
        self._db = dbm.open(dbAbsPath, "w")
        
    def secureSerializedObject(self, data, objKey, password):
        if not isinstance(objKey, bytes):
            objKey = bytes(objKey, "utf-8")
        iv = SHA(objKey).digest()[:16]
        key_enc = SHA(bytes(password + "AES-128-CBC-ENCRYPTION","utf-8")).digest()[:16]
        key_mac = SHA(bytes(password + "HMAC-SHA1-MAC","utf-8")).digest()[:16]
        return EncryptThenHmac(key_enc, iv, key_mac).encrypt(data)
        
    def unsecureSerializedObject(self, data, objKey, password):
        if not isinstance(objKey, bytes):
            objKey = bytes(objKey, "utf-8")
        iv = SHA(objKey).digest()[:16]
        key_enc = SHA(bytes(password + "AES-128-CBC-ENCRYPTION","utf-8")).digest()[:16]
        key_mac = SHA(bytes(password + "HMAC-SHA1-MAC","utf-8")).digest()[:16]
        decrypted = EncryptThenHmac(key_enc, iv, key_mac).decrypt(data)
        if not decrypted:
            raise Exception("Could not decrypt because mac invalid")
        return decrypted
    
    def add(self, objects):
        temp = {}
        result = self.__addToTemp(objects, temp)
        if result.succeeded():
            self._commitAddRequired.update(temp)
        return result
        
    def __addToTemp(self, objects, temp):
        for o in objects:
            if self.hasKey(self.getKey(o)):
                return LedgerOperationFailure("Key %s already exists" % self.getKey(o))
            serializedObj = self.serialize(o)
            temp[self.getKey(o)] = self.secureSerializedObject(serializedObj, self.getKey(o), self.__password)
        return LedgerOperationSuccess()
    
    def commitAdd(self):
        for key, secureSerialized in self._commitAddRequired.items():
            self._db[key] = secureSerialized
        self._save()
        self._commitAddRequired.clear()
        return LedgerOperationSuccess()
    
    def commitRemove(self):
        for key in self._commitRemoveRequired:
            del self._db[key]
        self._save()
        self._commitRemoveRequired.clear()
        return LedgerOperationSuccess()
    
    def keys(self):
        return self._db.keys()
    
    def hasKey(self, k):
        return k in self._db
    
    def get(self, key, default=None):
        temp = self._db.get(key, default)
        if temp != default:
            temp = self.unsecureSerializedObject(temp, key, self.__password) 
            temp = self.deserialize(temp)
        return temp
        
    def remove(self, objects):
        temp = set([])
        result = self.__removeToTemp(objects, temp)
        if result.succeeded():
            self._commitRemoveRequired.update(temp)
        return result
    
    def __removeToTemp(self, objects, temp):
        for o in objects:
            key = self.getKey(o)
            if not self.hasKey(key):
                return LedgerOperationFailure("Key %s does not exist in vault" % self.getKey(o))
            temp.add(key)
        return LedgerOperationSuccess()


class BitPointVault(SecureItemStorage):
    @classmethod
    def serialize(cls, o):
        return o.serialize()
    
    @classmethod
    def deserialize(cls, s):
        return BitPoint.deserialize(s)[0]
    
    @classmethod
    def getKey(cls, bp):
        return str(bp.serialNumber())


class LedgerLineStorage(SecureItemStorage):
    @classmethod
    def getKey(cls, ll):
        return str(ll.number())


class Ledger(PermanentObjectMixin):
    CRYPTO_CONTROL_FILE_NAME = "ledger_crypto_control.bin"
    #INITIAL_LEDGER_STATE = {
    #                        "ledgerLine":LedgerLine(0,None)
    #                        }
    INITIAL_ACCOUNTS = ["CIRCULATION","VAULT"]
    @classmethod
    def InitializeDb(cls, path, cert, privateKey, password):
        if cert.public_key().public_numbers() != privateKey.public_key().public_numbers():
            raise Exception("Private key and cert don't match")
        path = os.path.abspath(path)
        abspath = os.path.join(path, cls.CRYPTO_CONTROL_FILE_NAME)
        initialLedger = LedgerLine(None)
        for account in cls.INITIAL_ACCOUNTS:
            initialLedger.addAccount(account)
        ledgerDir = os.path.join(path, "ledger")
        vaultDir = os.path.join(path, "vault")
        initialState = {"ledgerLine":initialLedger,
                        "ledgerDir":ledgerDir,
                        "vaultDir":vaultDir,
                        "mintCertPaths":set()}
        if not os.path.exists(ledgerDir):
            os.mkdir(ledgerDir)
        if not os.path.exists(vaultDir):
            os.mkdir(vaultDir)
        LedgerLineStorage.InitializeStorage(ledgerDir, cert, privateKey, password)
        BitPointVault.InitializeStorage(vaultDir, cert, privateKey, password)
        
        cls.secureSaveState(abspath, cert, privateKey, password, **initialState)
        
    def __init__(self, dbDirectory, cert, password):
        self.__dir = dbDirectory
        self.__cert = cert
        self.__password = password
        self.__mintCertPaths = set()
        self.__bpVerifiers = dict()
        self.__load()
        
    def __nextLedgerLine(self):
        old = self.__ledgerLine
        newLedgerLine = LedgerLine(old)
        self.__ledgerStorage.add([old])
        commit = self.__ledgerStorage.commitAdd()
        if not commit.succeeded():
            raise Exception("Could not save ledger")
        self.__ledgerLine = newLedgerLine

    def __save(self):
        abspath = os.path.join(self.__dir, self.CRYPTO_CONTROL_FILE_NAME)
        self.secureSaveState(abspath, self.__cert, self.__privateKey, self.__password, ledgerLine=self.__ledgerLine,
                             ledgerDir=self.__ledgerDir, vaultDir=self.__vaultDir, mintCertPaths=self.__mintCertPaths)
        
    def __load(self):
        abspath = os.path.join(self.__dir, self.CRYPTO_CONTROL_FILE_NAME)
        if not os.path.exists(abspath):
            raise Exception("No ledger database in %s" % self.__dir)
        self.__privateKey, state = self.secureLoadState(abspath, self.__cert, self.__password)
        self.__ledgerDir = state["ledgerDir"]
        self.__vaultDir = state["vaultDir"]
        self.__mintCertPaths = state["mintCertPaths"]
        self.__bpVerifiers = dict()
        for path in self.__mintCertPaths:
            cert = loadCertFromFile(path)
            issuer = bytes(getCertSubject(cert)["commonName"],"utf-8")
            self.__bpVerifiers[issuer] = BitPointVerifier(cert)
        self.__ledgerStorage = LedgerLineStorage(self.__ledgerDir, self.__cert, self.__password)
        self.__vault = BitPointVault(self.__vaultDir, self.__cert, self.__password)
        self.__ledgerLine = state["ledgerLine"]
    
    def createAccount(self, publicKeyPEM):
        if publicKeyPEM in self.__ledgerLine.accounts():
            return LedgerOperationFailure("Account already exists")
        self.__ledgerLine.addAccount(publicKeyPEM)
        self.__save()
        return LedgerOperationSuccess()
    
    def getAccounts(self):
        return self.__ledgerLine.accounts()
    
    def getBalance(self, account):
        return self.__ledgerLine.getBalance(account)

    def printAccounts(self):
        for account in self.getAccounts():
            print("Account: %s\n\t\tBalance: " % account, self.getBalance(account))
    
    def __reconcileCirculation(self):
        return self.__ledgerLine.getBalance("CIRCULATION") == (-len(self.__vault.keys()))
    
    def registerMintCert(self, certpath):
        try:
            certObj = loadCertFromFile(certpath)
            issuer = bytes(getCertSubject(certObj)["commonName"], "utf-8")
            self.__bpVerifiers[issuer] = BitPointVerifier(certObj)
            self.__mintCertPaths.add(certpath)
            self.__save()
        except Exception:
            errMsg = traceback.format_exc()
            return LedgerOperationFailure("Could not register cert for mint: %s" % errMsg)
        return LedgerOperationSuccess()
    
    def withdrawCash(self, account, amount):
        if not account in self.__ledgerLine.accounts():
            return LedgerOperationFailure("No such account %s" % account)
        if not self.__reconcileCirculation():
            return LedgerOperationFailure("Already in a bad state. Circulation does not match deposits")
        if not type(amount) == int or amount < 0:
            return LedgerOperationFailure("Amount must be a positive integer.")
        if amount > self.getBalance(account):
            return LedgerOperationFailure("Not enough BitPoints in account %s to withdraw %d" % (account, amount))
        bitpointKeys = self.__vault.keys()[:amount]
        if len(bitpointKeys) < amount:
            return LedgerOperationFailure("Not enough Bitpoints in the vault for withdrawal")
        bitpoints = []
        for bitpointKey in bitpointKeys:
            bitpoints.append(self.__vault.get(bitpointKey))
        result = self.__vault.remove(bitpoints)
        if not result.succeeded():
            return result
        self.__ledgerLine.setTransaction(time.asctime(), "cash withdrawal", (account, "CIRCULATION", amount))
        self.__nextLedgerLine()
        self.__save()
        commit = self.__vault.commitRemove()
        if not commit.succeeded:
            return commit
        if not self.__reconcileCirculation():
            errMsgTemplate = "There was a mismatch. Circulation account is %d, bitpoints only total %d. " \
                             "Transaction reversed."
            errMsg = errMsgTemplate % (self.__ledgerLine.getBalance("CIRCULATION"),len(self.__vault.keys()))
            self.__ledgerLine.setTransaction(time.asctime(), "cash reverse", ("CIRCULATION", account, len(bitpoints)))
            self.__nextLedgerLine()
            self.__save()
            # attempt to remove added bitpoints
            result = self.__vault.add(bitpoints)
            if result.succeeded(): self.__vault.commitAdd()
            return LedgerOperationFailure(errMsg)
        return LedgerOperationSuccess(value=bitpoints)
        
    def depositCash(self, account, bitPoints):
        if not account in self.__ledgerLine.accounts():
            return LedgerOperationFailure("No such account %s" % account)
        if not self.__reconcileCirculation():
            return LedgerOperationFailure("Already in a bad state. Circulation does not match deposits")
        #try:
        #if 1:
        for bitPoint in bitPoints:
            if bitPoint.issuer() not in self.__bpVerifiers:
                return LedgerOperationFailure("Cannot verify bitpoint. Unknown issuer %s (known issuers: %s)" % (bitPoint.issuer(),self.__bpVerifiers.keys()))
            result, errMsg = self.__bpVerifiers[bitPoint.issuer()].verify(bitPoint)
            if not result:
                return LedgerOperationFailure(
                    "BitPoint %d did not verify (%s). Aborting" % (bitPoint.serialNumber(), errMsg))
        result = self.__vault.add(bitPoints)
        if not result.succeeded():
            return result
        commit = self.__vault.commitAdd()
        if not commit.succeeded:
            return commit
        #except Exception, e:
        #    print("Exception", e)
        #    return LedgerOperationFailure(str(e))
        self.__ledgerLine.setTransaction(time.asctime(), "cash deposit", ("CIRCULATION",account, len(bitPoints)))
        self.__nextLedgerLine()
        self.__save()
        if not self.__reconcileCirculation():
            errMsgTemplate = "There was a mismatch. Circulation account is %d, " \
                             "bitpoints only total %d. Transaction reversed."
            errMsg = errMsgTemplate % (self.__ledgerLine.getBalance("CIRCULATION"),len(self.__vault.keys()))
            self.__ledgerLine.setTransaction(time.asctime(), "vault reverse", (account, "CIRCULATION", len(bitPoints)))
            self.__nextLedgerLine()
            self.__save()
            # attempt to remove added bitpoints
            result = self.__vault.remove(bitPoints)
            if result.succeeded(): self.__vault.commitRemove()
            return LedgerOperationFailure(errMsg)
        return LedgerOperationSuccess()
    
    def transfer(self, srcAccount, dstAccount, amount, memo=""):
        if srcAccount not in self.__ledgerLine.accounts():
            return LedgerOperationFailure("No such account %s" % srcAccount)
        if dstAccount not in self.__ledgerLine.accounts():
            return LedgerOperationFailure("No such account %s" % dstAccount)
        if not type(amount) == int:
            return LedgerOperationFailure("Amount must be an integer.")
        if amount < 0:
            return LedgerOperationFailure("Cannot have a negative amount %d" % amount)
        try:
            self.__ledgerLine.setTransaction(time.asctime(), memo, (srcAccount, dstAccount, amount))
        except Exception as e:
            return LedgerOperationFailure("Failure with transaction: %s" % str(e))
        ledgerNumber = self.__ledgerLine.number()
        self.__nextLedgerLine()
        self.__save()
        return LedgerOperationSuccess(value=ledgerNumber)
    
    def generateReceipt(self, forAccount, ledgerNumber=None):
        if ledgerNumber == None:
            allNumbers = list(map(int, self.__ledgerStorage.keys()))
            allNumbers.sort()
            ledgerNumber = allNumbers[-1]
        ledgerNumber = str(ledgerNumber)
        if not self.__ledgerStorage.hasKey(ledgerNumber):
            return LedgerOperationFailure("No such ledger line %s" % ledgerNumber)
        ledger = self.__ledgerStorage.get(ledgerNumber)
        if not ledger:
            return LedgerOperationFailure("Could not restore ledger.")
        ledgerSerialized = self.__ledgerStorage.serialize(ledger.receiptForm(forAccount))
        signature = DefaultSign(ledgerSerialized, self.__privateKey)
        return LedgerOperationSuccess(value=(ledgerSerialized, signature))
    
    def searchLedger(self, lFilter):
        allNumbers = list(map(int, self.__ledgerStorage.keys()))
        allNumbers.sort()
        matches = []
        for num in allNumbers:
            ledger = self.__ledgerStorage.get(str(num))
            try:
                if lFilter(ledger): matches.append(num)
            except:
                pass
        return matches
    
    def getLedgerLine(self, num):
        return self.__ledgerStorage.get(str(num))


def main(BankCoreModule, args):
    #sys.path.append("../..")
    from getpass import getpass
    from Exchange import BitPoint
    if args[0] == "create":
        cert, key, path = args[1:4]
        cert = loadCertFromFile(cert)
        key = loadPrivateKeyFromPemFile(key)
        passwd = getpass()
        BankCoreModule.Ledger.InitializeDb(path, cert, key, passwd)
    elif args[0] == "vault_deposit":
        cert, path, bpFile = args[1:4]
        cert = loadCertFromFile(cert)
        passwd = getpass()
        bank = BankCoreModule.Ledger(path, cert, passwd)
        with open(bpFile, "rb") as f: bps = BitPoint.deserializeAll(f)
        print("depositing", len(bps), "bit points")
        result = bank.depositCash("VAULT", bps)
        if not result.succeeded():
            print("Deposit failed", result.msg())
        else:
            print("Vault balance", bank.getBalance("VAULT"))
    elif args[0] == "balances":
        cert, path = args[1:3]
        cert = loadCertFromFile(cert)
        passwd = getpass()
        bank = BankCoreModule.Ledger(path, cert, passwd)
        for account in bank.getAccounts():
            print("%s balance"%account, bank.getBalance(account))
    elif args[0] == "register_mint":
        bankcertpath, path, mintcertpath = args[1:4]
        passwd = getpass()
        bankcert = loadCertFromFile(bankcertpath)
        bank = Ledger(path, bankcert, passwd)
        result = bank.registerMintCert(mintcertpath)
        if not isinstance(result, LedgerOperationSuccess):
            print("Could not load certificate", result.msg())
        else:
            print("Mint cert registration successful?")
    elif args[0] == "create_account":
        accountName, cert, path = args[1:4]
        cert = loadCertFromFile(cert)
        passwd = getpass()
        bank = BankCoreModule.Ledger(path, cert, passwd)
        bank.createAccount(accountName)
    elif args[0] == "transfer":
        fromAccount, toAccount, amount, cert, path = args[1:6]
        cert = loadCertFromFile(cert)
        passwd = getpass()
        bank = BankCoreModule.Ledger(path, cert, passwd)
        amount = int(amount)
        result = bank.transfer(fromAccount, toAccount, amount)
        if not result.succeeded():
            print("Failed: ", result.msg())
        for account in [fromAccount, toAccount]:
            print("%s balance" % account, bank.getBalance(account))
    elif args[0] == "correct":
        cert, path = args[1:3]
        cert = loadCertFromFile(cert)
        passwd = getpass()
        bank = BankCoreModule.Ledger(path, cert, passwd)
        for account in bank.getAccounts():
            if account == "VAULT": continue
            bank.transfer("VAULT", account, 100)
    elif args[0] == "display_receipt":
        receiptFile, sigFile, cert = args[1:4]
        with open(receiptFile) as f:
            receiptData = f.read()
        with open(sigFile) as f:
            sigData=f.read()
        cert = loadCertFromFile(cert)
        verifier = RSA_SIGNATURE_MAC(cert.public_key())
        receipt = pickle.loads(receiptData)
        print("Receipt:", receipt.toHumanReadableString())
        if verifier.verify(sigData, SHA(receiptData).digest()):
            print("Receipt is signed by the bank.")
        else:
            print("Receipt is forged")
    elif args[0] == "test":
        full_test(args)

def full_test(args):
    # args = ["full_test",
    #         "./certs/signed_certs/5001cert",
    #         "./certs/signed_certs/5001pk",
    #         "bitpoints.10.Thu_Oct_19_19_17_39_2017",
    #         "./certs/signed_certs/6001cert"
    #     ]
    from getpass import getpass
    certPath, keyFile, bpsFile, fakeCertPath = args[1:5]
    cert = loadCertFromFile(certPath)
    key = loadPrivateKeyFromPemFile(keyFile)
    fakeCert = loadCertFromFile(fakeCertPath)
    with open(bpsFile,"rb") as f: bps = BitPoint.deserializeAll(f)
    passwd = getpass()
    fakePass = "This is an incorrect password for testing purposes"
    accountPEM = "Fady'sPEM"

    path = os.path.dirname("./test_bankcore_db/")
    # Overwrite directory if it already exists
    if os.path.exists(path):
        print("Previous test db found. Deleting and recreating folder")
        from shutil import rmtree
        rmtree(path)
    os.makedirs(path)

    # create a db with a wrong key/cert combination
    try:
        Ledger.InitializeDb(path, fakeCert, key, passwd)
    except Exception as e:
        print("Wrong combination of cert and key caught correctly! (%s)" % e)

    # Create a db
    Ledger.InitializeDb(path, cert, key, passwd)

    # Attempt to load bank with wrong password
    try:
        Ledger(path, cert, fakePass)
    except ValueError as e:
        print("Wrong password for this bank caught correctly! (%s)" % e)

    # Attempt to load bank with wrong cert
    try:
        Ledger(path, fakeCert, passwd)
    except Exception as e:
        print("Wrong certificate for this bank caught correctly! (%s)" % e)

    # Correctly load bank
    bank = Ledger(path, cert, passwd)

    # Check initial accounts are there
    assert(set(bank.getAccounts()) == set(Ledger.INITIAL_ACCOUNTS))

    # Add an account (SHOULD BE Public Key PEM BYTES)
    result = bank.createAccount(accountPEM)
    assert(isinstance(result, LedgerOperationSuccess))

    # Check the new account is there
    assert(accountPEM in bank.getAccounts())

    # Try to create a new account with the same PEM
    # (returns a LedgerOperationFailure object)
    result = bank.createAccount(accountPEM)
    assert(isinstance(result, LedgerOperationFailure))

    # Try to transfer money INTO non-existent account
    result = bank.transfer("VAULT", "Non-existentPEM", 1)
    assert(isinstance(result, LedgerOperationFailure))

    # Try to transfer money FROM non-existent account
    result = bank.transfer("Non-existentPEM", "VAULT", 2)
    assert(isinstance(result, LedgerOperationFailure))

    # All accounts should still be 0
    for account in bank.getAccounts():
        assert(bank.getBalance(account) == 0)

    # Transfer to and from valid accounts
    result = bank.transfer("VAULT", accountPEM, 3)
    assert(isinstance(result, LedgerOperationSuccess))
    assert(bank.getBalance(accountPEM) == 3)
    assert(bank.getBalance("VAULT") == -3)

    # Reload bank from file and check it correctly saved all changes
    bank = Ledger(path, cert, passwd)
    assert(set(bank.getAccounts()) == set(Ledger.INITIAL_ACCOUNTS + [accountPEM]))
    assert(bank.getBalance(accountPEM) == 3)
    assert(bank.getBalance("VAULT") == -3)

    # Transfer to and from valid accounts
    result = bank.transfer("VAULT", accountPEM, 5)
    assert(isinstance(result, LedgerOperationSuccess))

    # Register a mint cert (in this case we'll just use the same one...)
    result = bank.registerMintCert(certPath)
    assert(isinstance(result, LedgerOperationSuccess))

    # With that cert, we can deposit some BitPoints minted by that cert
    result = bank.depositCash("VAULT", bps)
    assert(isinstance(result, LedgerOperationSuccess))

    # Withdraw BitPoints
    result = bank.withdrawCash(accountPEM, 2)
    assert(isinstance(result, LedgerOperationSuccess))

    # Create a receipt
    result = bank.generateReceipt(accountPEM,0)
    assert(isinstance(result, LedgerOperationSuccess))
    receiptData, signatureData = result.value()[0], result.value()[1]
    receipt = pickle.loads(receiptData)
    print("Receipt:", receipt.toHumanReadableString())

    # Verify the receipt
    verifier = RSA_SIGNATURE_MAC(cert.public_key())
    try:
        verifier.verify(signatureData, SHA(receiptData).digest())
        print("Receipt is signed by the bank.")
    except AssertionError:
        print("Receipt is forged")

    # Try to withdraw more BitPoints than the bank has
    result = bank.withdrawCash("VAULT", 9999999999)
    try:
        assert(isinstance(result, LedgerOperationSuccess))
        raise(Exception("Over-withdrawal not caught!!!"))
    except AssertionError as e:
        print("Over-withdrawal caught correctly! (%s)" % result.msg())

    # Test LedgerLineSearch
    filter = lambda ledgerLine: ledgerLine.partOfTransaction("CIRCULATION")
    matches = bank.searchLedger(filter)
    assert(set(matches) == {2, 3})

    # Test getLedgerLine
    ledgerLine = bank.getLedgerLine(1)
    assert(ledgerLine.getTransactionAmount("VAULT") == -5)
    assert(ledgerLine.getTransactionAmount(accountPEM) == 5)

    # Debug output
    print("\nDebug:\n---------\n")
    filter = lambda ledgerLine: True
    allLines = bank.searchLedger(filter)
    for line in allLines:
        print("Ledger line ", line, ":\n", bank.getLedgerLine(line).toHumanReadableString())

    print()
    print("Full test completed successfully!")

    # In case we're in the REPL and want to keep playing
    return bank

if __name__ == "__main__":
    # import ourself. This is necessary for importing
    # with pickle. Some day, figure out something better.
    BankCore = sys.modules[__name__]
    main(BankCore, sys.argv[1:])
