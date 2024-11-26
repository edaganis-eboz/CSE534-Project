from enum import Enum
from scapy.all import *

class Secure_Association():
    def __init__(self, sc_ID, sa_ID, dest, key):
        self.sc_identifier = sc_ID # This might be useful
        self.sa_identifier = sa_ID #placeholder
        self.destination = dest #("MAC_ADDR", "IP_ADDR", "PORT")
        self.key = key

class Secure_Channel():
    def __init__(self, sc_ID):
        self.sc_identifier = sc_ID #placeholder
        self.associations = {}

class KE_Protocol_Messages(Enum):
    SA_KE_REQUEST = b'SA_KE_RQUEST' #standard length of 13
    SA_KE_ACCEPT = b'SA_KE_ACCEPT'
    SA_KE_PUBKEY = b'SA_KE_PUBKEY'
    SA_KE_SECRET = b'SA_KE_SECRET'

class PING_Messages(Enum):
    PING_REQUEST = b'PING_REQUEST'
    PING_REPLY = b'PING_REPLYYY'

## MAY NOT BE USED ##
class SA_INIT_STAGES(Enum):
    # Outgoing 
    STAGE_0 = 0 #Created Request Sent
    STAGE_1 = 1 #Accept Recieved, Pubkey Sent
    STAGE_2 = 2 #Shared Secret Recieved, fully initalized outgoing SA
    
    # Incomming
    STAGE_11 = 11 


##### HEADERS ####
    # IV is size 16
class SecTag(Packet):
    name = "SecTag"
    fields_desc = [
        ShortField("system_identifier", 0x0000),
        ShortField("port_number", 0x0000),
        ShortField("sa_identifier", 0x0000)
    ]

class ICV(Packet):
    name = "ICV"
    fields_desc = [
        StrFixedLenField("integrity_checksum_value", b"\x00" * 16, 16)
    ]