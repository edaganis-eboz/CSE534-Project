from enum import Enum

class Secure_Association():
    def __init__(self, sc_ID, sa_ID, dest, key, type):
        self.sc_identifier = sc_ID # This might be useful
        self.sa_identifier = sa_ID #placeholder
        self.destination = dest #("MAC_ADDR", "IP_ADDR", "PORT")
        self.key = key
        self.type = self.SA_Type(type)
        self.cipher = None
    class SA_Type(Enum):
        OUTGOING = 0
        INCOMMING = 1

class Secure_Channel():
    def __init__(self, sc_ID):
        self.sc_identifier = sc_ID #placeholder
        self.associations = {}

class KE_Protocol_Messages(Enum):
    SA_KE_REQUEST = b'SA_KE_REQUEST'
    SA_KE_ACCEPT = b'SA_KE_ACCEPT'
