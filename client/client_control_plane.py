from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from scapy.all import Ether, IP, UDP, sendp, Raw
from random import randint
from os import urandom
from util import *
import queue
import threading


class Key_Agreement_Entity():
    def __init__(self, identifier):
        self.Data_Plane = None
        self.KaY_indentifier = identifier
        self.CA_hosts = {}
        self.secure_channels = {}
        self.secure_channels[-1] = Secure_Channel(-1) # Special Channel for incomming SA's

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

    # TODO these get functions keep returning NoneType
    def get_SC(self, sc_ID):
        return self.secure_channels.get(sc_ID)
    
    def get_SA(self, sc_ID, sa_ID):
        secure_channel = self.get_SC(sc_ID)
        secure_association = secure_channel.associations.get(sa_ID)
        return secure_association
    
    def create_SA(self, sc_ID, dest, key):
        sa_ID = randint(10000, 65535) # TODO This rand int stuff needs to check if there is no SA/SC with the same identifier
        sa = Secure_Association(sc_ID, sa_ID, dest, key)
        sc = self.secure_channels[sc_ID]
        sc.associations[sa_ID] = sa
        return sa_ID

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
        sc = self.secure_channels[sc_ID]
        if sc == None:
            print("f")
        if len(sc.associations) == 0:
            print(f"Secure Channel {sc_ID} has no Secure Associations")
        else:
            print(f"Secure Channel: {sc_ID}")    
            for index, sa in enumerate(sc.associations.values()):
                print(f"[{index}] Secure Association ID: {sa.sa_identifier} -> {self.resolve_address(sa.destination)}")


class Client_Control_Plane():
    # KaY is on the control plane
    
    def __init__(self, Data_Plane, identifier):
        self.KaY = Key_Agreement_Entity(identifier)
        self.Data_Plane = Data_Plane
        self.RSA_Key = None

        # Threading Stuff
        self.lock = threading.Lock()
        self.running = True
        self.data_plane_listen = threading.Thread(target=self.get_traffic_from_data_plane, daemon=True)
        self.data_plane_listen.start()
    
    @staticmethod
    def get_src_info(frame):
        eth = frame.getlayer(Ether)
        ip = frame.getlayer(IP)
        transport = frame.getlayer(UDP)
    
        
        if eth and ip and transport:
            src_eth = eth.src        
            src_ip = ip.src          
            src_port = transport.sport  

            return (src_eth, src_ip, src_port)
        else:
            return None 
    
    
    def process_frame(self, frame):
        with self.lock:
            if Raw in frame:
                try:
                    protocol = KE_Protocol_Messages((frame[Raw].load)[:12])
                    if protocol == KE_Protocol_Messages.SA_KE_REQUEST:
                        self.key_exchange_accept(frame)
                    elif protocol == KE_Protocol_Messages.SA_KE_ACCEPT:
                        self.key_exchange_send_pubkey(frame)
                    elif protocol == KE_Protocol_Messages.SA_KE_PUBKEY:
                        self.key_exchange_send_encrypted_secret(frame)
                    elif protocol == KE_Protocol_Messages.SA_KE_SECRET:
                        self.key_exchange_create_outgoing(frame)
                    else:
                        print(f"Message: {protocol}")
                except ValueError:
                    pass


    def get_traffic_from_data_plane(self):
        while self.running:
            try:
                frame = self.Data_Plane.listener.queue.get(timeout=1)
                self.process_frame(frame)
            except queue.Empty:
                pass

    
    def create_outgoing_SA(self, sc_id, dst):
        try:
            sc = self.KaY.secure_channels[sc_id]
        except KeyError:
            print(f"Secure Channel with ID:{sc_id} does not exist")
        else:
            self.key_exchange_start(sc_id, dst)
    
    def send_via_SA(self, message, sc_id, sa_id):
        secure_association = self.KaY.secure_channels[sc_id].associations[sa_id]
        self.Data_Plane.send(message, None, secure_association=secure_association)
    
    # Key exchange is hella broken
    # This needs to be in try except blocks as well
    def key_exchange_start(self, sc_id, dst): # I dont know how I feel about this, this is done in plaintext, so it should be okay to be outisde of KaY
        message = KE_Protocol_Messages.SA_KE_REQUEST.value+str(sc_id).encode()
        self.Data_Plane.send(message, dst)

    def key_exchange_accept(self, frame):
        return_addr = self.get_src_info(frame)
        sc_id = (frame[Raw].load)[12:17]
        message = KE_Protocol_Messages.SA_KE_ACCEPT.value+ sc_id
        self.Data_Plane.send(message, return_addr)
        
    def key_exchange_send_pubkey(self, frame):
        return_addr = self.get_src_info(frame)
        sc_id = (frame[Raw].load)[12:17]
        try:
            # assert self.RSA_Key != None
            key_message = KE_Protocol_Messages.SA_KE_PUBKEY.value + sc_id + self.RSA_Key.publickey().export_key(format='PEM')
            self.Data_Plane.send(key_message, return_addr)
        except AssertionError:
            print("No key")

    def key_exchange_send_encrypted_secret(self, frame):
        return_addr = self.get_src_info(frame)
        sc_id = (frame[Raw].load)[12:17]
        pubkey = RSA.import_key((frame[Raw].load)[17:])
        secret = urandom(32)
        cipher = PKCS1_OAEP.new(pubkey)
        encrypted_secret = cipher.encrypt(secret)
        message = KE_Protocol_Messages.SA_KE_SECRET.value+ sc_id + encrypted_secret
        self.Data_Plane.send(message, return_addr)
        
        # create a incomming SA
        self.KaY.create_SA(-1, return_addr, secret)

    def key_exchange_create_outgoing(self, frame):
        return_addr = self.get_src_info(frame)
        sc_id = int((frame[Raw].load)[12:17])
        encrypted_secret = (frame[Raw].load)[17:]
        cipher = PKCS1_OAEP.new(self.RSA_Key)
        shared_secret = cipher.decrypt(encrypted_secret)
        if shared_secret != None:
            self.KaY.create_SA(sc_id, return_addr, shared_secret)
        else:
            print("Key Exchange Failed")


