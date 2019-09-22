from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import BOOL, STRING, TIME

class GameCommandPacket(PacketType):
    DEFINITION_IDENTIFIER = "client.GameCommandPacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
              ("original", BOOL),
              ("message", STRING)
             ]

    @classmethod
    def create_game_command_packet(cls, s):
        return cls( # whatever arguments needed to construct the packet)
    
    def command(self):
        return # whatever you need to get the command for the game
    
class GameResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = "server.GameResponsePacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
              ("original", BOOL),
              ("message", STRING),
              ("time", TIME)
             ]

    @classmethod
    def create_game_response_packet(cls, response, status):
        return cls( # whatever you need to construct the packet )
    
    def game_over(self):
        return # whatever you need to do to determine if the game is over
    
    def status(self):
        return # whatever you need to do to return the status
    
    def response(self):
        return # whatever you need to do to return the response