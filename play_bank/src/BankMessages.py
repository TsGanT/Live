'''
Created on Apr 1, 2014

@author: sethjn
'''
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import BOOL, INT16, INT64, UINT16, UINT64, STRING, BUFFER, ListFieldType as LIST
from playground.network.packet.fieldtypes.attributes import Optional

class OpenSession(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.OpenSession"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce", UINT64),
            ("Login",STRING),
            ("PasswordHash",BUFFER)
            ]

class SessionOpen(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.SessionOpen"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("Account",STRING)
            ]

class ListAccounts(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.ListAccounts"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("User",STRING({Optional:True}))
            ]

class ListUsers(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.ListUsers"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("Account",STRING({Optional:True}))
            ]

class ListAccountsResponse(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.ListAccountsResponse"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("Accounts",LIST(STRING))
            ]

class ListUsersResponse(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.ListUsersResponse"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("Users",LIST(STRING))
            ]

class CurrentAccount(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.CurrentAccount"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64)
            ]

class CurrentAccountResponse(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.CurrentAccountResponse"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("Account",STRING)
            ]

class SwitchAccount(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.SwitchAccount"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("Account",STRING)
            ]

class BalanceRequest(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.BalanceRequest"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64)
            ]

class BalanceResponse(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.BalanceResponse"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("Balance",INT64)
            ]

class AdminBalanceRequest(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.AdminBalanceRequest"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64)
            ]

class AdminBalanceResponse(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.AdminBalanceResponse"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("Accounts",LIST(STRING)),
            ("Balances",LIST(INT64))
            ]

class TransferRequest(PacketType):
    DEFINITION_IDENTIFIER= "apps.bank.TransferRequest"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("DstAccount",STRING),
            ("Amount",UINT16),
            ("Memo",STRING)
            ]

class DepositRequest(PacketType):
    DEFINITION_IDENTIFIER= "apps.bank.DepositRequest"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("bpData",BUFFER)
            ]

class WithdrawalRequest(PacketType):
    DEFINITION_IDENTIFIER= "apps.bank.WithdrawlRequest"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("Amount",INT16)
            ]

class WithdrawalResponse(PacketType):
    DEFINITION_IDENTIFIER= "apps.bank.WithdrawalResponse"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("bpData",BUFFER)
            ]

class SetUserPasswordRequest(PacketType):
    DEFINITION_IDENTIFIER= "apps.bank.SetUserPasswordRequest"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("loginName", STRING),
            ("oldPwHash", BUFFER),
            ("newPwHash", BUFFER),
            ("NewUser", BOOL)
            ]

class CreateAccountRequest(PacketType):
    DEFINITION_IDENTIFIER= "apps.bank.CreateAccountRequest"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("AccountName", STRING),
            ]

class CurAccessRequest(PacketType):
    DEFINITION_IDENTIFIER= "apps.bank.CurAccessRequest"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("UserName", STRING({Optional:True})),
            ("AccountName", STRING({Optional:True})),
            ]

class CurAccessResponse(PacketType):
    DEFINITION_IDENTIFIER= "apps.bank.CurAccessResponse"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("Accounts", LIST(STRING)),
            ("Access", LIST(STRING))
            ]

class ChangeAccessRequest(PacketType):
    DEFINITION_IDENTIFIER= "apps.bank.ChangeAccessRequest"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("UserName", STRING),
            ("Account", STRING({Optional:True})),
            ("AccessString", STRING)
            ]

class RequestSucceeded(PacketType):
    DEFINITION_IDENTIFIER = "apps.bank.RequestSucceeded"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ]

class Receipt(PacketType):
    DEFINITION_IDENTIFIER= "apps.bank.Receipt"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("Receipt", BUFFER),
            ("ReceiptSignature", BUFFER)
            ]

class LedgerRequest(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.LedgerRequest"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("Account",STRING({Optional:True}))]

class LedgerResponse(PacketType):
    DEFINITION_IDENTIFIER="apps.bank.LedgerResponse"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce",UINT64),
            ("ServerNonce",UINT64),
            ("RequestId",UINT64),
            ("Lines",LIST(BUFFER))]

class LoginFailure(PacketType):
    DEFINITION_IDENTIFIER = "apps.bank.LoginFailure"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
            ("ClientNonce", UINT64),
            ("ErrorMessage", STRING)
            ]
    
class RequestFailure(PacketType):
    DEFINITION_IDENTIFIER = "apps.bank.RequestFailure"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce", UINT64),
            ("ServerNonce", UINT64),
            ("RequestId", UINT64),
            ("ErrorMessage", STRING)]
    
class PermissionDenied(PacketType):
    DEFINITION_IDENTIFIER = "apps.bank.PermissionDenied"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce", UINT64),
            ("ServerNonce", UINT64),
            ("RequestId", UINT64),
            ("ErrorMessage", STRING)]
    
class ServerError(PacketType):
    DEFINITION_IDENTIFIER = "apps.bank.ServerError"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ErrorMessage", STRING)]
    
class Close(PacketType):
    DEFINITION_IDENTIFIER = "apps.bank.Close"
    DEFINITION_VERSION="1.0"
    FIELDS = [
            ("ClientNonce", UINT64),
            ("ServerNonce", UINT64)]
