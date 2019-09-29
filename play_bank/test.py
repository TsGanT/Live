from CipherUtil import loadCertFromFile
from BankCore import LedgerLineStorage, LedgerLine
from OnlineBank import BankClientProtocol, OnlineBankConfig
import playground
import getpass, sys, os, asyncio

bankconfig = OnlineBankConfig()
bank_addr =     bankconfig.get_parameter("CLIENT", "bank_addr")
bank_port = int(bankconfig.get_parameter("CLIENT", "bank_port"))
bank_stack     =     bankconfig.get_parameter("CLIENT", "stack","default")
bank_username  =     bankconfig.get_parameter("CLIENT", "username")

certPath = os.path.join(bankconfig.path(), "bank.cert")
bank_cert = loadCertFromFile(certPath)


async def example_transfer(bank_client, src, dst, amount, memo):^M
    await playground.create_connection(^M
            lambda: bank_client,^M
            bank_addr,^M
            bank_port,^M
            family='default'^M
        )^M
    print("Connected. Logging in.")^M
        ^M
    try:^M
        await bank_client.loginToServer()^M
    except Exception as e:^M
        print("Login error. {}".format(e))^M
        return False^M
^M
    try:^M
        await bank_client.switchAccount(src)^M
    except Exception as e:^M
        print("Could not set source account as {} because {}".format(^M
            src,^M
            e))^M
        return False^M
    ^M
    try:^M
        result = await bank_client.transfer(dst, amount, memo)^M
    except Exception as e:^M
        print("Could not transfer because {}".format(e))^M
        return False^M
        ^M
    return result^M
    ^M
def example_verify(bank_client, receipt_bytes, signature_bytes, dst, amount, memo):^M
    if not bank_client.verify(receipt_bytes, signature_bytes):^M
        raise Exception("Bad receipt. Not correctly signed by bank")^M
    ledger_line = LedgerLineStorage.deserialize(receipt_bytes)^M
    if ledger_line.getTransactionAmount(dst) != amount:^M
        raise Exception("Invalid amount. Expected {} got {}".format(amount, ledger_line.getTransactionAmount(dst)))^M
    elif ledger_line.memo(dst) != memo:^M
        raise Exception("Invalid memo. Expected {} got {}".format(memo, ledger_line.memo()))^M
    return True^M
    ^M
if __name__=="__main__":^M
    src, dst, amount, memo = sys.argv[1:5]^M
    amount = int(amount)
    username = bank_username # could override at the command line^M
    password = getpass.getpass("Enter password for {}: ".format(username))^M
    bank_client = BankClientProtocol(bank_cert, username, password)
    loop = asyncio.get_event_loop()^M
    result = loop.run_until_complete(^M
        example_transfer(bank_client, src, dst, amount, memo))^M
    if result:
        example_verify(bank_client, result.Receipt, result.ReceiptSignature, dst, amount, memo)^M
        print("Receipt verified.")
