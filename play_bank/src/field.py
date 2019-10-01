from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import BOOL, STRING, UINT32, BUFFER

class GameCommandPacket(PacketType):
    DEFINITION_IDENTIFIER = "client.GameCommandPacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
              ("message", STRING)
             ]

    @classmethod
    def create_game_command_packet(cls, s):
        return cls(message = s )
    
    def command(self):
        return self.message
    
class GameResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = "server.GameResponsePacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
              ("responsee", STRING),
              ("statuss", STRING)
             ]

    @classmethod
    def create_game_response_packet(cls, response, status):
        return cls( responsee=response, statuss = status )
    
    def game_over(self):
        return self.statuss != "playing"
    
    def status(self):
        return self.statuss
    
    def response(self):
        return self.responsee

class GameInitRequestPacket(PacketType):
    DEFINITION_IDENTIFIER = "sever.GameInitRequestPacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("username_string", STRING),
    ]

class GamePaymentRequestPacket(PacketType):
    DEFINITION_IDENTIFIER = "sever.GamePaymentRequestPacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("unique_id", STRING),
        ("account", STRING),
        ("amount", UINT32)
    ]

class GamePaymentResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = "sever.gamepaymentresponse"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("receipt", BUFFER),
        ("receipt_sig", BUFFER),
    ]

def create_game_init_packet(username):
    return GameInitRequestPacket(username_string=username)

def process_game_init(pkt):
    return "stang47"

def create_game_require_pay_packet(unique_id, account, amount):
    return GamePaymentRequestPacket(unique_id=unique_id, account=account, amount=amount)

def process_game_require_pay_packet(pkt):
    return pkt.unique_id, pkt.account, pkt.amount

def create_game_pay_packet(receipt, receipt_signature):
    return GamePaymentResponsePacket(receipt=receipt, receipt_sig=receipt_signature)

def process_game_pay_packet(pkt):
    return pkt.receipt, pkt.receipt_sig

def create_game_response(response, status):
    return GameResponsePacket(responsee=response, statuss=status)

def process_game_response(pkt):
    return pkt.res, pkt.sta

def create_game_command(command):
    return GameCommandPacket(message=command)

def process_game_command(pkt):
    return pkt.message