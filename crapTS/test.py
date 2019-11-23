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


def loadFile(path):
    with open(path, "r") as key_file:
        return key_file.read().encode("ASCII")

RootcertPath = "./20194_root.cert"
Team4CertPath = "./team4_signed.cert"
Team4PrivateKeyPath = "./key_team4.pem"

Rootcert = loadFile(RootcertPath)
Team4Cert = loadFile(Team4CertPath)
Team4PrivateKey = loadFile(Team4PrivateKeyPath)


publickRoot = x509.load_pem_x509_certificate(Rootcert, default_backend()).public_key()
Cteam4 = x509.load_pem_x509_certificate(Team4Cert, default_backend())
print(Cteam4.subject, type(Cteam4.subject))

callback = print

#pk_bytes = publickCert.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)# commaon name -> issuer name   prefix

# plaintext = private_key.decrypt(
#     ciphertext,
#     padding.OAEP(
#     mgf=padding.MGF1(algorithm=hashes.SHA256()),
#          algorithm=hashes.SHA256(),
#          label=None)
# )

# try:
#     print("begin verify cert")
#     publickRoot.verify(
#         publickCert.signature,
#         publickCert.tbs_certificate_bytes,        #plain text
#         padding.PKCS1v15(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
#         hashes.SHA256()
#     )
#     print("verify client's signature success!!!!")
# except Exception as error:
#     print("Wrong signature from client!!!!!!!")