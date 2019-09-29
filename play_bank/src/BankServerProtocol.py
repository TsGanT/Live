from BankMessages import *
from Exchange import BitPoint

from BankCore import Ledger, LedgerLine # For unshelving
from PermissionCheck import PermissionCheck, PermissionsSet, PermissionsExist

from playground.network.common.Protocol import StackingProtocol
from playground.network.common.PlaygroundAddress import PlaygroundAddress
from playground.network.packet.PacketType import FIELD_NOT_SET

from ErrorHandler import ErrorHandler
from PacketHandler import SimplePacketHandler

from contextlib import contextmanager
import traceback, logging, asyncio, os, time

RANDOM_u64 = lambda: int.from_bytes(os.urandom(8), "big")

PasswordBytesHash = lambda pw: SHA(pw).digest()
PasswordHash = lambda pw: PasswordBytesHash(bytes(pw, "utf-8"))

def logSecure(msg):
    logging.critical(msg)
    
debugPrint = print

def callLater(delay, f):
    asyncio.get_event_loop().call_later(delay, f)

class BankServerProtocol(StackingProtocol, SimplePacketHandler, ErrorHandler):

    STATE_UNINIT = "Uninitialized"
    STATE_OPEN = "Open"
    STATE_ERROR = "Error"
    
    ADMIN_PW_ACCOUNT = "__admin__"
    ADMIN_ACCOUNTS = ["VAULT"]
    
    WITHDRAWAL_LIMIT = 1000
    WITHDRAWAL_WINDOW = 6*3600 # 6 hours in seconds
    
    TIMEOUT = 60*5 # 5 minutes of no activity
    
    def handler_pre(initial_states, permissions=None, current_account=False):
        def real_decorator(f):
            def wrapped_function(self, protocol, msgObj):
                validated = self._pre_validate(
                    initial_states, 
                    permissions, 
                    current_account,
                    msgObj)
                if not validated: return
                result = f(self, protocol, msgObj)
                return result
            return wrapped_function
        return real_decorator
        
    def handler_post(state):
        def real_decorator(f):
            def wrapped_function(self, protocol, msgObj):
                result = f(self, protocol, msgObj)
                result = self._post_validate(result, state)
                return result
            return wrapped_function
        return real_decorator
            
    
    def __init__(self, pwDb, bank):
        debugPrint("server proto init")
        SimplePacketHandler.__init__(self)
        #self.setHandler(self)
        self.__pwDb = pwDb
        self.__connData = {"ClientNonce":0,
                           "ServerNonce":0,
                           "AccountName":None,
                           "LoginName":None}
        self.__crossAccountRequest = None
        self.__state = self.STATE_UNINIT
        self.__bank = bank
        self.__withdrawlTracking = {}
        self.__lastActivity = time.time()
        self.registerPacketHandler(OpenSession, self.__handleOpenSession)
        self.registerPacketHandler(ListAccounts, self.__handleListAccounts)
        self.registerPacketHandler(ListUsers, self.__handleListUsers)
        self.registerPacketHandler(CurrentAccount, self.__handleCurrentAccount)
        self.registerPacketHandler(SwitchAccount, self.__handleSwitchAccount)
        self.registerPacketHandler(BalanceRequest, self.__handleBalanceRequest)
        self.registerPacketHandler(TransferRequest, self.__handleTransferRequest)
        self.registerPacketHandler(DepositRequest, self.__handleDeposit)
        self.registerPacketHandler(WithdrawalRequest, self.__handleWithdrawal)
        self.registerPacketHandler(AdminBalanceRequest, self.__handleAdminBalanceRequest)
        self.registerPacketHandler(CreateAccountRequest, self.__handleCreateAccount)
        self.registerPacketHandler(SetUserPasswordRequest, self.__handleSetUserPassword)
        self.registerPacketHandler(ChangeAccessRequest, self.__handleChangeAccess)
        self.registerPacketHandler(CurAccessRequest, self.__handleCurAccess)
        self.registerPacketHandler(LedgerRequest, self.__handleLedgerRequest)
        self.registerPacketHandler(Close, self.__handleClose)

    def connection_made(self, transport):
        debugPrint("server proto connection made", transport)
        StackingProtocol.connection_made(self, transport)
        self.transport = transport
        callLater(60, self.__checkTimeout) # check our 5 minute timeout every 1 minute

    def sendPacket(self, packet):
        self.transport.write(packet.__serialize__())
        debugPrint("Sent", packet.DEFINITION_IDENTIFIER)
        
    def handlePacket(self, protocol, packet):
        self.__logSecure("Received packet %s" % packet)
        super().handlePacket(protocol, packet)

    def data_received(self, data):
        self.__lastActivity = time.time()
        debugPrint("server proto data_received")
        try:
            self.handleData(None, data)
        except Exception as e:
            print(traceback.format_exc())
            
    def __checkTimeout(self):
        idle_time = time.time() - self.__lastActivity
        
        debugPrint("Check timeout. Idle {} seconds.".format(idle_time))
        if idle_time > self.TIMEOUT:
            debugPrint("Close connection.")
            self.transport.close()
        else:
            callLater(60, self.__checkTimeout)
    
    @contextmanager    
    def __setCrossAccount(self, xAccount):
        if self.__crossAccountRequest != None:
            raise Exception("Cross account request already set.")
        try:
            self.__crossAccountRequest = xAccount
            yield xAccount
        finally:
            self.__crossAccountRequest = None
            
    def __getCrossAccount(self):
        return self.__crossAccountRequest
        
    def __getCurrentAccount(self):
        return self.__connData["AccountName"]
        
    def __clearWithdrawlLimit(self, account):
        if account in self.__withdrawlTracking:
            del self.__withdrawlTracking[account]
            
    def __logSecure(self, msg):
        fullMsg = "SERVER SECURITY (Session %(ClientNonce)d-%(ServerNonce)d"
        fullMsg += " User [%(LoginName)s] Account [%(AccountName)s] "
        fullMsg = fullMsg % self.__connData
        peer = self.transport and self.transport.get_extra_info("peername") or "<NOT CONNECTED>"
        fullMsg += " Peer [%s]): " % (peer,)
        fullMsg += msg
        logSecure(fullMsg)
     
    def __error(self, errMsg, requestId = 0, fatal=True):
        debugPrint("server proto error ", errMsg)
        self.__logSecure(errMsg)
        if self.__state == self.STATE_ERROR:
            return None
        if self.__state == self.STATE_UNINIT:
            response = LoginFailure()
            response.ClientNonce = self.__connData["ClientNonce"]
        else:
            response = RequestFailure()
            response.ClientNonce = self.__connData["ClientNonce"]
            response.ServerNonce = self.__connData["ServerNonce"]
            response.RequestId = requestId
        response.ErrorMessage = errMsg
        self.sendPacket(response)
        if fatal:
            debugPrint("server proto error Closing connection!")
            self.__state = self.STATE_ERROR
            callLater(1, self.transport.close)
        return None
    
    def __sendPermissionDenied(self, errMsg, requestId=0):
        if self.__state == self.STATE_ERROR:
            return None
        self.__logSecure("Permission denied, %s" % errMsg)
        response = PermissionDenied()
        response.ClientNonce = self.__connData.get("ClientNonce",0)
        response.ServerNonce = self.__connData.get("ServerNonce",0)
        response.RequestId = requestId
        response.ErrorMessage = errMsg
        self.sendPacket(response)
        return None
    
    def __getSessionAccount(self, msgObj):
        if self.__state != self.STATE_OPEN:
            self.__error("Session not logged-in", msgObj.RequestId)
            return None, None
        if self.__connData["ClientNonce"] != msgObj.ClientNonce:
            self.__error("Invalid connection data", msgObj.RequestId)
            return None, None
        if self.__connData["ServerNonce"] != msgObj.ServerNonce:
            self.__error("Invalid connection data", msgObj.RequestId)
            return None, None
            
        if self.__getCrossAccount() != None:
            # We're interested in an account that's different from our session account
            account = self.__getCrossAccount()
        else:
            account = self.__connData["AccountName"]
            
        userName = self.__connData["LoginName"]
        if account and self.__pwDb.hasAccount(account):
            access = self.__pwDb.currentAccess(userName, account)
        else: access = ''
        debugPrint("server __getSessionAccount acc:", account, "access:", access)
        return (account, access)
    
    def __validateAdminPeerConnection(self):
        peer = self.transport.get_extra_info("peername")
        debugPrint("Server's Peer:", peer)
        if not peer: return False
        addr = PlaygroundAddress.FromString(peer[0])
        # Uhhh this is a weird check...
        #if addr[1] != ADMIN_ZONE: return False
        return True

    def __getAdminPermissions(self, requestId=0, fatal=True):
        if not self.__validateAdminPeerConnection():
            if fatal: self.__error("Unauthorized connection location. Will be logged", requestId)
            return None
        userName = self.__connData.get("LoginName",None)
        if not userName:
            if fatal: self.__error("Attempt for admin without logging in. Will be logged", requestId)
            return None
        if not self.__pwDb.hasUser(userName):
            if fatal: self.__error("Attempt for admin from not user. Will be logged", requestId)
            return None
        access = self.__pwDb.currentAccess(userName, self.ADMIN_PW_ACCOUNT)
        if not access:
            if fatal: self.__error("Attempt for admin without any admin permissions. Will be logged", requestId)
            return None
        return access
    
    def __createResponse(self, msgObj, responseType):
        response = responseType()
        response.ClientNonce = msgObj.ClientNonce
        response.ServerNonce = msgObj.ServerNonce
        return response
        
    def __login(self, msgObj):
        # if this isn't a login message, something else is wrong
        if not isinstance(msgObj, OpenSession):
            return self.__error("Only OpenSession requests allowed in uninit state.")
            
        # record the ClientNonce in the connection state. Necessary.
        self.__connData["ClientNonce"] = msgObj.ClientNonce
        
        # check if the 
        if not self.__pwDb.hasUser(msgObj.Login):
            debugPrint("Bank has no record of a user {}".format(msgObj.Login))
            return self.__error("Invalid Login. User does not exist or password is wrong")
            
        passwordHash = self.__pwDb.currentUserPassword(msgObj.Login)
        # debugPrint(passwordHash, len(passwordHash), type(passwordHash), "VS", msgObj.PasswordHash, len(msgObj.PasswordHash), type(msgObj.PasswordHash))
        
        if passwordHash != msgObj.PasswordHash:
            debugPrint("server proto __handleOpenSession pw not equal")
            return self.__error("Invalid Login. User does not exist or password is wrong")
        return True
        
    def __checkPermissions(self, msgObj, requirements):
        account, access = self.__getSessionAccount(msgObj)
        if account == None or access == None:
            return self.__error("Connection Error. Wrong state or invalid handling.")
        debugPrint("Checking permissions on account {} with access {}".format(account, access))
        debugPrint("Permission Requirement: {}".format(requirements))
        if not PermissionCheck.check(requirements,access):
            debugPrint("Initial Check Failed. Try Admin")
            # the initial permissions check failed. Can we try admin?
            admin_access = None
            if PermissionCheck.checkIncludesAdmin(requirements):
                admin_access = self.__getAdminPermissions(msgObj.RequestId, fatal=False)
                # include both incase there is an "and" of normal
                # and admin permissions
                if admin_access: 
                    access += admin_access
                    debugPrint("Admin possible. Combined access: {}".format(access))
                
            if not admin_access or not PermissionCheck.check(requirements, access):
                    
                self.__logSecure("Trying to process {} for {} requires '{}' access, but has {}".format(
                    msgObj.DEFINITION_IDENTIFIER,
                    self.__connData["LoginName"], 
                    requirements,
                    access))
                return self.__sendPermissionDenied("Requires '{}' access".format(requirements), msgObj.RequestId)
        return True
        
    def __sendNoAccountResponse(self, msgObj):
        account = self.__connData["AccountName"]
        if account == '':
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = "Account must be selected or specified"
            return self.sendPacket(response)
        return True
        
    def _pre_validate(self, initial_states, permissions, current_account, msgObj):
        if self.__state not in initial_states:
            return self.__error("Could not handle message {}. Illegal state {}".format(
                msgObj.DEFINITION_IDENTIFIER,
                self.__state)
            )
        
        # if self.__state is UNINIT, do the login first
        if self.__state == self.STATE_UNINIT:
            if not self.__login(msgObj):
                return False # already sent back an error
        
        if permissions != None:
            if not self.__checkPermissions(msgObj, permissions):
                return False # already sent back an error
                
        if current_account and self.__connData.get("AccountName",'') == '':
            return self.__sendNoAccountResponse(msgObj)
            
        # if a cross account is specified, it must always be something other than''
        if self.__getCrossAccount() == '':
            return self.__sendNoAccountResponse(msgObj)
                
        return True
        
    def _post_validate(self, result, state):
        self.__state = state
        return result
    
    @handler_pre(initial_states=[STATE_UNINIT])
    @handler_post(state=STATE_OPEN)
    def __handleOpenSession(self, protocol, msgObj):
        self.__connData["ServerNonce"] = RANDOM_u64()
        self.__connData["AccountName"] = ""
        self.__connData["LoginName"] = msgObj.Login
        
        response = SessionOpen()
        response.ClientNonce = msgObj.ClientNonce
        response.ServerNonce = self.__connData["ServerNonce"]
        response.Account = ""
        self.__logSecure("Request for open with nonce %d, sending back %d" % (msgObj.ClientNonce,
                                                                              self.__connData["ServerNonce"]))
        self.sendPacket(response)
    
    @handler_pre(initial_states=[STATE_OPEN])
    def __handleCurrentAccount(self, protocol, msgObj):
        account, access = self.__getSessionAccount(msgObj)
        response = self.__createResponse(msgObj, CurrentAccountResponse)
        response.Account = account
        response.RequestId = msgObj.RequestId
        self.sendPacket(response)
        
    def __createListAccountsResponse(self, msgObj, userName):
        accountAccessData = self.__pwDb.currentAccess(userName)
        accountNames = list(accountAccessData.keys())
        response = self.__createResponse(msgObj, ListAccountsResponse)
        response.RequestId = msgObj.RequestId
        response.Accounts = accountNames
        return response
    
    @handler_pre(initial_states=[STATE_OPEN])
    def __handleListAccounts(self, protocol, msgObj):
        if msgObj.User != FIELD_NOT_SET:
            return self.__admin_handleListAccounts(protocol, msgObj)

        userName = self.__connData["LoginName"]
        response = self.__createListAccountsResponse(msgObj, userName)   
        self.sendPacket(response)
        
    @handler_pre(initial_states=[STATE_OPEN], permissions='B')
    def __admin_handleListAccounts(self, protocol, msgObj):
        response = self.__createListAccountsResponse(msgObj, msgObj.User)
        self.sendPacket(response)
        
    def __createListUsersResponse(self, msgObj, accountToList):
        users = []
        for name in self.__pwDb.iterateUsers(accountToList):
            users.append(name)
        response = self.__createResponse(msgObj, ListUsersResponse)
        response.RequestId = msgObj.RequestId
        response.Users = users
        return response
    
    @handler_pre(initial_states=[STATE_OPEN])
    def __handleListUsers(self, protocol, msgObj):
        if msgObj.Account == FIELD_NOT_SET:
            # use current account, unless account is not set, in which case
            # it has to be administrator
            accountToList = self.__getCurrentAccount()
        else:
            accountToList = msgObj.Account
        self.__logSecure("list users requested for account %s" % accountToList)
            
        if accountToList == '':
            return self.__admin_handleListUsers(protocol, msgObj)
        else:
            # We might be asking about an account that's different.
            # Use crossAccountRequest
            with self.__setCrossAccount(accountToList) as crossAccount:
                return self.__xaccount_handleListUsers(protocol, msgObj)
            
    @handler_pre(initial_states=[STATE_OPEN], permissions=PermissionsSet('B','A'))
    def __admin_handleListUsers(self, protocol, msgObj):
        response = self.__createListUsersResponse(msgObj, '')
        self.sendPacket(response)
        
    @handler_pre(initial_states=[STATE_OPEN], permissions='a')
    def __xaccount_handleListUsers(self, protocol, msgObj):
        response = self.__createListUsersResponse(msgObj, self.__getCrossAccount())
        self.__logSecure("sending list of %d users" % len(response.Users))
        self.sendPacket(response)
        
    def __createSwitchAccountResponse(self, msgObj, account):
        debugPrint("Setting account name to {}".format(account))
        self.__connData["AccountName"] = account
        self.__logSecure("Account Switched to {}".format(account))
        response = self.__createResponse(msgObj, RequestSucceeded)
        response.RequestId = msgObj.RequestId
        self.sendPacket(response)
    
    @handler_pre(initial_states=[STATE_OPEN])
    def __handleSwitchAccount(self, protocol, msgObj):
        desiredAccount = msgObj.Account
        
        if desiredAccount.startswith("__"):
            self.__logSecure("ATTEMPT TO ACCESS SPECIAL ACCOUNT %s" % desiredAccount)
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = "Could not switch accounts"
            return self.sendPacket(response)
            
        elif desiredAccount in self.ADMIN_ACCOUNTS:
            return self.__admin_handleSwitchAccount(protocol, msgObj)
        elif desiredAccount not in self.__bank.getAccounts():
            self.__logSecure("Attempt to access unknown account %s" % desiredAccount)
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = "No such account {}".format(desiredAccount)
            return self.sendPacket(response)
            
        else:
            with self.__setCrossAccount(desiredAccount) as crossAccount:
                debugPrint("Swtiching to {}".format(crossAccount))
                return self.__xaccount_handleSwitchAccount(protocol, msgObj)
    
    @handler_pre(initial_states=[STATE_OPEN], permissions='S')    
    def __admin_handleSwitchAccount(self, protocol, msgObj):
        self.__createSwitchAccountResponse(msgObj, msgObj.Account)
        
    
    @handler_pre(initial_states=[STATE_OPEN], permissions=PermissionsSet(PermissionsExist(),"A")) 
    def __xaccount_handleSwitchAccount(self, protocol, msgObj):
        # Allow access to an account if the user has any regular permission on the account
        # or the user has admin "A"
        self.__createSwitchAccountResponse(msgObj, self.__getCrossAccount())   
    
    @handler_pre(initial_states=[STATE_OPEN], permissions='b', current_account=True) 
    def __handleBalanceRequest(self, protocol, msgObj):
        account = self.__getCurrentAccount()
        balance = self.__bank.getBalance(account) or 0
        debugPrint("Balance for account", account, ":", balance)
        response = self.__createResponse(msgObj, BalanceResponse)
        response.RequestId = msgObj.RequestId
        response.Balance = balance
        self.__logSecure("Sending back balance")
        self.sendPacket(response)
    
    @handler_pre(initial_states=[STATE_OPEN], permissions='B')    
    def __handleAdminBalanceRequest(self, protocol, msgObj):
        accountList = self.__bank.getAccounts()
        balancesList = []
        for account in accountList:
            balancesList.append(self.__bank.getBalance(account))
        response = self.__createResponse(msgObj, AdminBalanceResponse)
        response.RequestId = msgObj.RequestId
        response.Accounts = list(accountList)
        response.Balances = balancesList
        self.__logSecure("Sending back %d balances" % len(balancesList))
        self.sendPacket(response)
    
    @handler_pre(initial_states=[STATE_OPEN], permissions='t', current_account=True)    
    def __handleTransferRequest(self, protocol, msgObj):
        dstAccount = msgObj.DstAccount
        amount = msgObj.Amount
        account = self.__getCurrentAccount()
        debugPrint("Transfer {} from {} to {}".format(amount, account, dstAccount))
        
        if not dstAccount in self.__bank.getAccounts():
            return self.__error("Invalid destination account %s" % dstAccount, msgObj.RequestId,
                                fatal=False) 
        if amount < 0: 
            return self.__error("Invalid (negative) amount %d" % amount, msgObj.RequestId,
                                fatal=False)
        if amount > self.__bank.getBalance(account):
            return self.__error("Insufficient Funds to pay %d" % amount, msgObj.RequestId,
                                fatal=False)
                                
        result = self.__bank.transfer(account,dstAccount, amount, msgObj.Memo)
        
        if not result.succeeded():
            return self.__error("Bank transfer failed: " + result.msg(), msgObj.RequestId,
                                fatal=True)
        # Assume single threaded. The last transaction will still be the one we care about
        result = self.__bank.generateReceipt(dstAccount)
        if not result.succeeded():
            return self.__error("Bank transfer failed: " + result.msg(), msgObj.RequestId,
                                fatal=True)
        receipt, signature = result.value()
        response = self.__createResponse(msgObj, Receipt)
        response.RequestId = msgObj.RequestId
        response.Receipt = receipt
        response.ReceiptSignature = signature
        self.__logSecure("Transfer succeeded, sending receipt")
        self.sendPacket(response)
        
    @handler_pre(initial_states=[STATE_OPEN], permissions='d', current_account=True)
    def __handleDeposit(self, protocol, msgObj):
        account = self.__getCurrentAccount()
        
        bps = []
        bpData = msgObj.bpData
        # debugPrint(bpData[:15], "...", bpData[-15:], len(bpData), type(bpData))
        while bpData:
            newBitPoint, offset = BitPoint.deserialize(bpData)
            bpData = bpData[offset:]
            bps.append(newBitPoint)
        result = self.__bank.depositCash(account,bps)
        if not result.succeeded():
            self.__logSecure("Deposit failed, %s" % result.msg())
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = result.msg()
        else:
            result = self.__bank.generateReceipt(account)
            if not result.succeeded():
                self.__logSecure("Could not generate receipt? %s" % result.msg())
                response = self.__createResponse(msgObj, RequestFailure)
                response.RequestId = msgObj.RequestId
                response.ErrorMessage = result.msg()
            else:
                self.__logSecure("Deposit complete. Sending Signed Receipt")
                receipt, signature = result.value()
                response = self.__createResponse(msgObj, Receipt)
                response.RequestId = msgObj.RequestId
                response.Receipt = receipt
                response.ReceiptSignature = signature
        self.sendPacket(response)
    
    @handler_pre(initial_states=[STATE_OPEN], permissions='d', current_account=True)    
    def __handleWithdrawal(self, protocol, msgObj):
        account = self.__getCurrentAccount()
        if self.__withdrawlTracking.get(account,0)+msgObj.Amount > self.WITHDRAWAL_LIMIT:
            self.__logSecure("Attempt to withdraw over the limit. Current: %d, requested: %d, limit: %d" % 
                             (self.__withdrawlTracking.get(account, 0), msgObj.Amount, self.WITHDRAWAL_LIMIT))
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = "Over Limit"
            return self.sendPacket(response)

        result = self.__bank.withdrawCash(account,msgObj.Amount)
        if not result.succeeded():
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = result.msg()
        else:
            if account not in self.__withdrawlTracking:
                self.__withdrawlTracking[account] = 0
                callLater(self.WITHDRAWAL_WINDOW, lambda: self.__clearWithdrawlLimit(account))
            self.__withdrawlTracking[account] += msgObj.Amount
            bitPoints = result.value()
            bpData = b""
            for bitPoint in bitPoints:
                bpData += bitPoint.serialize()
            response = self.__createResponse(msgObj, WithdrawalResponse)
            response.RequestId = msgObj.RequestId
            response.bpData = bpData
        self.sendPacket(response)
        
    def __isValidUsername(self, name):
        for letter in name:
            if not letter.isalnum() and not letter == "_":
                return False
        return True
        
    def __createSetUserPasswordResponse(self, msgObj, userName):
        pwHash = msgObj.newPwHash
        self.__pwDb.createUser(userName, pwHash, modify=True)
        self.__pwDb.sync()
        self.__logSecure("Password changed")
        
        okResponse = self.__createResponse(msgObj, RequestSucceeded)
        okResponse.RequestId = msgObj.RequestId
        self.sendPacket(okResponse)
    
    @handler_pre(initial_states=[STATE_OPEN])    
    def __handleSetUserPassword(self, protocol, msgObj):
        # requires that the user is changing his own password, or Admin('A') access
        userName = msgObj.loginName
        newUser = msgObj.NewUser
        self.__logSecure("Received change password request. Current user %s, user to change [%s]" % 
                    (self.__connData["LoginName"], userName))
        errorResponse = self.__createResponse(msgObj, RequestFailure)
        errorResponse.RequestId = msgObj.RequestId
        
        if not userName:
            userName = self.__connData["LoginName"]
        
        if (newUser or userName != self.__connData["LoginName"]):
            return self.__admin_handleSetUserPassword(protocol, msgObj)
            

        elif msgObj.oldPwHash == '':
            # Cannot allow this.
            self.__logSecure("Attempt to change username %s without previous hash" % userName)
            errorResponse.ErrorMessage = "No password hash specified"
            return self.sendPacket(errorResponse)
            
        elif self.__pwDb.currentUserPassword(userName) != msgObj.oldPwHash:
            self.__logSecure("Incorrect previous password for %s password change" % userName)
            errorResponse.ErrorMessage = "Invalid Password"
            return self.sendPacket(errorResponse)
            
        return self.__createSetUserPasswordResponse(msgObj, userName)
    
    @handler_pre(initial_states=[STATE_OPEN], permissions='A')        
    def __admin_handleSetUserPassword(self, protocol, msgObj):
        userName = msgObj.loginName
        newUser = msgObj.NewUser
        
        errorResponse = self.__createResponse(msgObj, RequestFailure)
        errorResponse.RequestId = msgObj.RequestId
        
        if newUser and self.__pwDb.hasUser(userName):
            self.__logSecure("Tried to create user %s that already exists" % userName)
            errorResponse.ErrorMessage = "User %s already exists" % userName
            return self.sendPacket(errorResponse)
        elif newUser and not self.__isValidUsername(userName):
            self.__logSecure("Attempt to create user with invalid name [%s]" % userName)
            errorResponse.ErrorMessage = "Username invalid. Only letters, numbers, and underscores."
            return self.sendPacket(errorResponse)
        elif not newUser and not self.__pwDb.hasUser(userName):
            self.__logSecure("Attempt to change password for non-existent user [%s]" % userName)
            errorResponse.ErrorMessage = "User %s does not exist" % userName
            return self.sendPacket(errorResponse)
            
        return self.__createSetUserPasswordResponse(msgObj, userName)
    
    @handler_pre(initial_states=[STATE_OPEN], permissions='A')
    def __handleCreateAccount(self, protocol, msgObj):
        response = self.__createResponse(msgObj, RequestSucceeded)
        newAccountName = msgObj.AccountName
        if self.__pwDb.hasAccount(newAccountName):
            self.__logSecure("Attempt to create account that already exists")
            response = self.__createResponse(msgObj, RequestFailure)
            response.ErrorMessage = "That account already exists"
        result = self.__bank.createAccount(newAccountName)
        if result.succeeded():
            self.__logSecure("New account %s created" % newAccountName)
            if not self.__pwDb.hasUser(newAccountName):
            # should only happen if we manually added a user to pwDB
                self.__pwDb.createAccount(newAccountName)
            self.__pwDb.sync()
        else:
            self.__logSecure("Internal Failure in creating account %s" % newAccountName)
            response = self.__createResponse(msgObj, RequestFailure)
            response.ErrorMessage = "Could not create account. Internal error"
        response.RequestId = msgObj.RequestId
        self.sendPacket(response)
        
    def __createCurAccessResponse(self, msgObj, userName, accountName):
        accounts = []
        accountsAccess = []
        if accountName:
            accounts.append(accountName)
            accountsAccess.append(self.__pwDb.currentAccess(userName, account))
        else:
            accessMulti = self.__pwDb.currentAccess(userName)
            for accountName, accountAccessString in accessMulti.items():
                accounts.append(accountName)
                accountsAccess.append(accountAccessString)
    
        response = self.__createResponse(msgObj, CurAccessResponse)
        response.RequestId = msgObj.RequestId
        response.Accounts = accounts
        response.Access = accountsAccess
        return response
    
    @handler_pre(initial_states=[STATE_OPEN])    
    def __handleCurAccess(self, protocol, msgObj):
        # Four cases.
        # 1. Check the access of another user across all accounts (Admin)
        # 2. Check the access of another user on a specific account ('a' on that account)
        # 3. Check my access on a specific account 
        # 5. Check my access on all accounts
        
        currentUser    = self.__connData["LoginName"]
        checkUser      = msgObj.UserName != FIELD_NOT_SET and msgObj.UserName or currentUser
        checkAccount   = msgObj.AccountName != FIELD_NOT_SET and msgObj.AccountName or ''
        
        # case 1. UserName specific, UserName not my name, no Account Specified
        if checkUser != currentUser and checkAccount == '':
            return self.__admin_handleCurAccess(protocol, msgObj)
            
        # case 2. UserName specific, AccountSpecific
        if checkUser != currentUser:
            with self.__setCrossAccount(checkAccount) as crossAccount:
                return self.__xaccount_handleCurAccess(protocol, msgObj)
                
        # cases 3-4 don't require specific permissions   
        response = self.__createCurAccessResponse(msgObj, currentUser, checkAccount)
        self.__logSecure("Sending back access information for {} on {} accounts".format(
            currentUser, 
            len(response.Accounts)))
        self.sendPacket(response)
    
    @handler_pre(initial_states=[STATE_OPEN], permissions='A')    
    def __admin_handleCurAccess(self, protocol, msgObj):
        response = self.__createCurAccessResponse(msgObj, msgObj.UserName, '')
        self.__logSecure("Sending back access information for %s on %d accounts".format(
            msgObj.UserName, 
            len(response.Accounts)))
        self.sendPacket(response)
    
    @handler_pre(initial_states=[STATE_OPEN], permissions='a')    
    def __xaccount_handleCurAccess(self, protocol, msgObj):
        response = self.__createCurAccessResponse(msgObj, msgObj.UserName, msgObj.Account)
        self.__logSecure("Sending back access information for {} on account {}".format(
            msgObj.UserName, 
            msgObj.Account))
        self.sendPacket(response)
        
    
    @handler_pre(initial_states=[STATE_OPEN])    
    def __handleChangeAccess(self, protocol, msgObj):
        # Two cases.
        # 1. Change the access for another user on the current account ('a' or 'A' access)
        # 2. Change the access for another user on a different account ('a' or 'A' access on cross account)
        
        # get the current account. It might be nothing (''). That's ok
        # Set a cross account; the one sent in the message if specified, otherwise the current account
        # if it's empty, we'll fail on permissions check as cross accounts must always
        # be non-empty
        account = self.__getCurrentAccount()
        changeAccount = msgObj.Account != FIELD_NOT_SET and msgObj.Account or account

        with self.__setCrossAccount(changeAccount) as crossAccount:
            # if the account is empty ('') permission will fail here.
            return self.__xaccount_handleChangeAccess(protocol, msgObj)
    
    @handler_pre(initial_states=[STATE_OPEN], permissions=PermissionsSet('a','A'))      
    def __xaccount_handleChangeAccess(self, protocol, msgObj):
        changeUser  = msgObj.UserName
        account     = self.__getCrossAccount()
        
        if not self.__pwDb.isValidAccessSpec(msgObj.AccessString, account):
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = "Invalid access string %s" % msgObj.AccessString
            self.__logSecure("Tried to change access to invalid %s" % msgObj.AccessString)
            return self.sendPacket(response)
            
        self.__pwDb.configureAccess(changeUser, account, msgObj.AccessString)
        self.__pwDb.sync()
        response = self.__createResponse(msgObj, RequestSucceeded)
        response.RequestId = msgObj.RequestId
        self.__logSecure("User {} access to {} changed to {}".format(
            changeUser, 
            account, 
            msgObj.AccessString))
        self.sendPacket(response)

    @handler_pre(initial_states=[STATE_OPEN])
    def __handleLedgerRequest(self, protocol, msgObj):
        userName = self.__connData["LoginName"]
        accountToGet = msgObj.Account != FIELD_NOT_SET and msgObj.Account or None
        self.__logSecure("Request ledger for user %s and account %s" % (userName, accountToGet))
        
        if not accountToGet:
            return self.__admin_handleLedgerRequest(protocol, msgObj)
        else:
            with self.__setCrossRequest(accountToGet) as crossRequest:
                self.__xaccount_handleLedgerRequest(protocol, msgObj)
    
    @handler_pre(initial_states=[STATE_OPEN], permissions='A')    
    def __admin_handleLedgerRequest(self, protocol, msgObj):
        # return all lines
        lFilter = lambda lline: True
        return self.__createLedgerResponse(msgObj, '', lFilter)
        
    @handler_pre(initial_states=[STATE_OPEN], permissions=PermissionsSet('a','A'))
    def __xaccount_handleLedgerRequest(self, protocol, msgObj):
        accountToGet = msgObj.Account != FIELD_NOT_SET and msgObj.Account or None
        lFilter = lambda lline: lline.partOfTransaction(accountToGet)
        return self.__createLedgerResponse(msgObj, accountToGet, lFilter)
        
    def __createLedgerResponse(self, msgObj, accountToGet, lFilter):
        userName = self.__connData["LoginName"]
        lineNums = self.__bank.searchLedger(lFilter)
        lines = []
        for lineNum in lineNums:
            line = self.__bank.getLedgerLine(lineNum)
            lines.append(line.toHumanReadableString(accountToGet))
        response = self.__createResponse(msgObj, LedgerResponse)
        response.RequestId = msgObj.RequestId
        response.Lines = lines
        self.__logSecure("User %s getting ledger for %s (%d lines" % (userName, accountToGet, len(lines)))
        self.sendPacket(response)
    
    @handler_pre(initial_states=[STATE_OPEN])
    @handler_post(STATE_UNINIT)
    def __handleClose(self, protocol, msg):
        debugPrint("server __handleClose", msg.DEFINITION_IDENTIFIER)
        msgObj = msg
        self.__logSecure("Close Connection")
        if self.transport: self.transport.close()