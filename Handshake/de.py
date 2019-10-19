from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, UINT8, BUFFER, UINT16, BOOL
from playground.network.packet.fieldtypes.attributes import Optional

class PoopPacketType(PacketType):
    DEFINITION_IDENTIFIER = "poop"
    DEFINITION_VERSION = "1.0"

class PoopHandshakePacket(PoopPacketType):
    # your definition here
    DEFINITION_IDENTIFIER = "poop"
    DEFINITION_VERSION = "1.0"
    NOT_STARTED = 0
    SUCCESS = 1
    ERROR = 2

    FIELDS = [
        ("SYN", UINT8({Optional: True})),
        ("ACK", UINT8({Optional: True})),
        ("status", UINT8),
        ("error", STRING({Optional: True})),
    ]

p = PoopHandshakePacket()
p.SYN = 1
p.ACK = 1
P.status = 1
p.error = 0

f = p.__serialize__()
print(PoopPacketType.Deserializer(f))