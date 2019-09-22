from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import BOOL, STRING

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