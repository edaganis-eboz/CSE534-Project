from random import randint
from enum import Enum
from os import urandom

class Secure_Association():
    def __init__(self, sc_ID, sa_ID, dest, key, type):
        self.sc_identifier = sc_ID # This might be useful
        self.sa_identifier = sa_ID #placeholder
        self.destination = dest #("MAC_ADDR", "IP_ADDR", "PORT")
        self.key = key
        self.type = self.SA_Type(0)
        self.cipher = None
    class SA_Type(Enum):
        OUTGOING = 0
        INCOMMING = 1

class Secure_Channel():
    def __init__(self, sc_ID):
        self.sc_identifier = sc_ID #placeholder
        self.associations = {}

class Key_Agreement_Entity():
    def __init__(self, identifier):
        self.Data_Plane = None
        self.KaY_indentifier = identifier
        self.CA_hosts = {}
        self.secure_channels = {}

    def load_known_hosts(self):
        # This will be the hosts in the Connectivity Association (CA), this is filled with "discovery" that KaY does
        # In our case, the hosts will be pre-discovered and data will be in hosts.txt, note that since self is in the
        # CA, self will be in there
        try:
            with open('hosts.txt', 'r') as f:
                for line in f:
                    parts = line.split()
                    self.CA_hosts[parts[0]] = (parts[1], parts[2], int(parts[3]))
        except Exception as e:
            print('Failed to load hosts.txt')

    def update_hosts(self):
        # The controllers (local or global) will have a record of the hosts, this will fetch that record  
        pass

    # We def need some error checking for these functions
    def create_SC(self):
        sc_ID = randint(10000, 65535)
        sc = Secure_Channel(sc_ID)
        self.secure_channels[sc_ID] = sc
        return sc_ID

    def get_SC(self, sc_ID):
        return self.secure_channels.get(sc_ID)
    
    def create_SA(self, sc_ID, dest, key, type):
        sa_ID = randint(10000, 65535)
        sa = Secure_Association(sc_ID, sa_ID, dest, key)
        sc = self.secure_channels[sc_ID]
        sc.associations[sa_ID] = sa
        return sa_ID

    def get_SA(self, sc_ID, sa_ID):
        secure_channel = self.get_SC(sc_ID)
        secure_association = secure_channel.associations.get(sa_ID)
        return secure_association
    
    def resolve_address(self, destination):
        for KaY_indentifier in self.CA_hosts:
            if destination == self.CA_hosts[KaY_indentifier]:
                return f"{destination}({KaY_indentifier})"
        return f"{destination}(Unknown)"
    
    #### PRINTING FUNCTIONS ####
    def print_CA(self):
        for index, host in enumerate(self.CA_hosts):
            print(f"[{index}] {host}: {self.CA_hosts[host]}")
    
    def print_SCs(self):
        if len(self.secure_channels) == 0:
            print("No Secure Channels")
        else:
            for index, sc in enumerate(self.secure_channels):
                print(f"[{index}] Secure Channel ID: {sc}")

    def print_SAs(self, sc_ID):
        sc = self.get_SC(sc_ID)
        if len(sc.associations) == 0:
            print(f"Secure Channel {sc_ID} has no Secure Associations")
        else:
            print(f"Secure Channel: {sc_ID}")    
            for index, sa in enumerate(sc.associations.values()):
                print(f"[{index}] Secure Association ID: {sa.sa_identifier} -> {self.resolve_address(sa.destination)}")


class Client_Control_Plane():
    # KaY is on the control plane
    def __init__(self, Data_Plane, identifier, RSA_Key):
        self.KaY = Key_Agreement_Entity(identifier)
        self.Data_Plane = Data_Plane
    class KE_Protocol_Messages(Enum):
        SA_KE_REQUEST = b'SA_KE_REQUEST'
        SA_KE_ACCEPT = b'SA_KE_ACCEPT'

    # Key exchange is hella broken
    # This needs to be in try except blocks as well
    def key_exchange_start(self, dest): # I dont know how I feel about this, this is done in plaintext, so it should be okay to be outisde of KaY
        self.Data_Plane.send_cleartext(self.KE_Protocol_Messages.SA_KE_REQUEST, dest)
        response = self.Data_Plane.get_response()
        if response == self.KE_Protocol_Messages.SA_KE_ACCEPT:
            self.Data_Plane.send_cleartext(RSA_Key)
            encrypted_shared_secret = self.Data_Plane.get_response()
            shared_secret = None
            return shared_secret
        else:
            return None
        
    def key_exchange_respond(self, request_frame):
        self.Data_Plane.send_cleartext(self.KE_Protocol_Messages.SA_KE_ACCEPT)
        pubkey = self.Data_Plane.get_response()
        secret = urandom(256)
        encrypted_secret = encrypt(pubkey, secret)
        self.Data_Plane.send_cleartext(encrypted_secret)
        # create a incomming SA


    def create_SA(self, sc_ID, dest, type):
        shared_secret = self.key_exchange(dest)
        if shared_secret != None:
            self.KaY.create_SA(sc_ID, dest, shared_secret, type)
        else:
            print("Key Exchange Failed")

        