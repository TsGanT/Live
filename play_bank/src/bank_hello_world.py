from CipherUtil import loadCertFromFile
from BankCore import LedgerLineStorage, LedgerLine
from OnlineBank import BankClientProtocol, OnlineBankConfig
import playground
import getpass, sys, os, asyncio

bankconfig = OnlineBankConfig()
bank_addr =     "20194.0.0.19000"
bank_port = 777#int(bankconfig.get_parameter("CLIENT", "777"))
bank_stack     =     "default"
bank_username  =     "stang47"
certPath = "/home/student_20194/Shi_Tang/Live/play_bank/src/20194_online_bank.cert"

#/Shi_Tang/Live/play_bank/src

certPath = os.path.join(bankconfig.path(), "bank.cert")
bank_cert = loadCertFromFile(certPath)


async def example_transfer(bank_client, src, dst, amount, memo):
    await playground.create_connection(
            lambda: bank_client,
            bank_addr,
            bank_port,
            family='default'
        )
    print("Connected. Logging in.")
        
    try:
        await bank_client.loginToServer()
    except Exception as e:
        print("Login error. {}".format(e))
        return False

    try:
        await bank_client.switchAccount(src)
    except Exception as e:
        print("Could not set source account as {} because {}".format(
            src,
            e))
        return False
    
    try:
        result = await bank_client.transfer(dst, amount, memo)
    except Exception as e:
        print("Could not transfer because {}".format(e))
        return False
        
    return result
    
def example_verify(bank_client, receipt_bytes, signature_bytes, dst, amount, memo):
    if not bank_client.verify(receipt_bytes, signature_bytes):
        raise Exception("Bad receipt. Not correctly signed by bank")
    ledger_line = LedgerLineStorage.deserialize(receipt_bytes)
    if ledger_line.getTransactionAmount(dst) != amount:
        raise Exception("Invalid amount. Expected {} got {}".format(amount, ledger_line.getTransactionAmount(dst)))
    elif ledger_line.memo(dst) != memo:
        raise Exception("Invalid memo. Expected {} got {}".format(memo, ledger_line.memo()))
    return True
    
async def paymentInit(src, dst, amount, memo):
    amount = int(amount)
    username = bank_username  # could override at the command line
    password = getpass.getpass("Enter password for {}: ".format(username))
    bank_client = BankClientProtocol(bank_cert, username, password)
    result = await example_transfer(bank_client, src, dst, amount, memo)
    if result:
        example_verify(bank_client, result.Receipt, result.ReceiptSignature, dst, amount, memo)
        print("Receipt verified.")
        return result.Receipt, result.ReceiptSignature
