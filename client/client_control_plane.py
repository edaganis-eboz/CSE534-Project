from random import randint
class Secure_Association():
    def __init__(self, sc_ID, sa_ID, dest):
        self.sc_identifier = sc_ID # This might be useful
        self.sa_identifier = sa_ID #placeholder
        self.destination = dest #("MAC_ADDR", "IP_ADDR", "PORT")
        self.key = b'0123456789ABCDEF'
        self.cipher = None

class Secure_Channel():
    def __init__(self, sc_ID):
        self.sc_identifier = sc_ID #placeholder
        self.associations = {}

class Key_Agreement_Entity():
    def __init__(self, identifier):
        self.KaY_indentifier = identifier
        self.hosts = {}
        self.secure_channels = {}

    def load_known_hosts(self):
        # This will be the hosts in the Connectivity Association (CA), this is filled with "discovery" that KaY does
        # In our case, the hosts will be pre-discovered and data will be in hosts.txt, note that since self is in the
        # CA, self will be in there
        try:
            with open('hosts.txt', 'r') as f:
                for line in f:
                    parts = line.split()
                    self.hosts[parts[0]] = (parts[1], parts[2], int(parts[3]))
        except Exception as e:
            print('Failed to load hosts.txt')

    def MKA(self):
        pass


    # We def need some error checking for these functions
    def create_SC(self):
        sc_ID = randint(10000, 65535)
        sc = Secure_Channel(sc_ID)
        self.secure_channels[sc_ID] = sc
        return sc_ID

    def get_SC(self, sc_ID):
        return self.secure_channels.get(sc_ID)
    
    def create_SA(self, sc_ID, dest):
        sa_ID = randint(10000, 65535)
        sa = Secure_Association(sc_ID, sa_ID, dest)
        SC = self.secure_channels[sc_ID]
        SC.associations[sa_ID] = sa
        return sa_ID

    def get_SA(self, sc_ID, sa_ID):
        secure_channel = self.get_SC(sc_ID)
        secure_association = secure_channel.associations.get(sa_ID)
        return secure_association

class Client_Control_Plane():
    # KaY is on the control plane
    def __init__(self, identifier):
        self.KaY = Key_Agreement_Entity(identifier)