'''
Created on Mar 27, 2014

@author: sethjn
'''
import pickle, sys

sys.path.append("../..")

from CipherUtil import *

import struct


class PermanentObjectMixin(object):
    PERM_CERT_KEY = "__PERM__CERT_KEY__"
    PERM_PRIVATE_KEY_KEY = "__PERM__PRIVATE_KEY_KEY__"
    RESERVED_KEYS = [PERM_CERT_KEY, PERM_PRIVATE_KEY_KEY]
    SIGNATURE_PACK = "<Q"
    AES_SIZE = 16

    @classmethod
    def getSalt(cls):
        return SHA(b"SALTSALTSALTSALT" + bytes(cls.__name__,"utf-8")).digest()

    @classmethod
    def getIV(cls):
        return SHA(b"IVIVIVIVIVIVIVIV" + bytes(cls.__name__,"utf-8")).digest()[:cls.AES_SIZE]

    @classmethod
    def secureSaveState(cls, filename, cert, privateKey, password, **state):
        for key in cls.RESERVED_KEYS:
            if key in state.keys():
                raise Exception("Reserved key %s used in save state" % key)
        state[cls.PERM_CERT_KEY] = serializeCert(cert)
        state[cls.PERM_PRIVATE_KEY_KEY] = serializePrivateKey(privateKey)
        data = pickle.dumps(state)
        fileKey = PBKDF2(password, cls.getSalt())[:cls.AES_SIZE]

        encrypter = EncryptThenRsaSign(fileKey, cls.getIV(), privateKey)
        encryptedAndSignedData = encrypter.encrypt(data)
        fileContents = encryptedAndSignedData + struct.pack(cls.SIGNATURE_PACK, encrypter.mac.MAC_SIZE)

        with open(filename, "wb+") as f:
            f.write(fileContents)

    @classmethod
    def secureLoadState(cls, filename, cert, password):
        with open(filename, "rb") as f:
            contents = f.read()
        packSize = struct.calcsize(cls.SIGNATURE_PACK)
        body, signatureSizeStructString = contents[:-packSize], contents[-packSize:]

        publicKey = cert.public_key()
        fileKey = PBKDF2(password, cls.getSalt())[:cls.AES_SIZE]
        decrypter = EncryptThenRsaSign(fileKey, cls.getIV(), publicKey)

        data = decrypter.decrypt(body)
        if data == None:
            raise Exception("Decryption error. Make sure you're using the right bank cert and password "
                            "or the correct decryption settings set in CipherUtil")
        state = pickle.loads(data)
        if state[cls.PERM_CERT_KEY] != serializeCert(cert):
            raise Exception("Certificate mismatch")
        del state[cls.PERM_CERT_KEY]
        privateKey = getPrivateKeyFromPemBytes(state[cls.PERM_PRIVATE_KEY_KEY])
        del state[cls.PERM_PRIVATE_KEY_KEY]
        return privateKey, state
