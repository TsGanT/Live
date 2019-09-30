from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import BOOL, STRING, UINT32

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

class PlayerPacket(PacketType):
    DEFINITION_IDENTIFIER = "client.PlayerPacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("playername", STRING)
    ]

class GameChargeRequestPacket(PacketType):
    DEFINITION_IDENTIFIER = "client.GameChargeRequestPacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("uniqueID", STRING),
        ("account", STRING),
        ("ammount", UINT32),
        ]

class GameChargeResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = "server.GameChargeResponsePacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("receipt", STRING),
        ("receipt_sig", STRING)
    ]

def create_player_packet(username):
    return PlayerPacket(playername = username)


def process_game_init(pkt):
    return "stang47"


def create_game_require_charge_packet(unique_id, account, amount):
    return GameChargeRequestPacket(unique_id=unique_id, account=account, amount=amount)


def process_game_require_charge_packet(pkt):
    return pkt.unique_id, pkt.account, pkt.amount


def create_game_charge_packet(receipt, receipt_signature):
    return GameChargeResponsePacket(receipt=receipt, receipt_sig=receipt_signature)


def process_game_pay_packet(pkt):
    return pkt.receipt, pkt.receipt_sig


def create_game_response(response, status):
    return GameResponsePacket(responsee=response, statuss=status)


def process_game_response(pkt):
    return pkt.responsee, pkt.statuss


def create_game_command(command):
    return GameCommandPacket(message=command)


def process_game_command(pkt):
    return pkt.message