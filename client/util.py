from enum import Enum
from scapy.all import *
from scapy.all import Ether, IP

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
    SA_KE_REQUEST = 0x0
    SA_KE_ACCEPT = 0x1
    SA_KE_PUBKEY = 0x2
    SA_KE_SECRET = 0x3

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
class SecTag(Packet):
    name = "SecTag"
    fields_desc = [
        ShortField("system_identifier", 0x0000),
        ShortField("sa_identifier", 0x0000),
        ByteField('rekey_flag', 0x00)
    ]
bind_layers(Ether, SecTag, type=0x88E5)

class KE_Header(Packet):
    name = "KE_Header"
    fields_desc = [
        ByteField("stage", 0x00),
        ShortField("system_identifier", 0x0000),
        ShortField("sa_identifier", 0x0000)
    ]

bind_layers(IP, KE_Header, proto=200)