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
        sa_ID = randint(10000, 65535) # TODO This rand int stuff needs to check if there is no SA/SC with the same identifier
        sa = Secure_Association(sc_ID, sa_ID, dest, key, type)
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
                    message = KE_Protocol_Messages(frame[Raw].load)
                    if message == KE_Protocol_Messages.SA_KE_REQUEST:
                        self.key_exchange_accept(frame)
                    elif message == KE_Protocol_Messages.SA_KE_ACCEPT:
                        self.key_exchange_send_pubkey()
                    else:
                        print(f"Message: {message}")
                except ValueError:
                    pass


    def get_traffic_from_data_plane(self):
        while self.running:
            try:
                frame = self.Data_Plane.listener.queue.get(timeout=1)
                self.process_frame(frame)
            except queue.Empty:
                pass

    # Key exchange is hella broken
    # This needs to be in try except blocks as well
    def key_exchange_start(self, dst): # I dont know how I feel about this, this is done in plaintext, so it should be okay to be outisde of KaY
        self.Data_Plane.send_cleartext(KE_Protocol_Messages.SA_KE_REQUEST.value, dst)

    def key_exchange_accept(self, frame):
        return_addr = self.get_src_info(frame)
        self.Data_Plane.send_cleartext(KE_Protocol_Messages.SA_KE_ACCEPT.value, return_addr)
        
    def key_exchange_send_pubkey(self):
        print("Enter Pubkey func")
        #self.Data_Plane.send_cleartext(self.RSA_Key)

    def key_exchange_send_encrypted_secret(self):
        secret = urandom(256)
        encrypted_secret = None #encrypt(pubkey, secret)
        self.Data_Plane.send_cleartext(encrypted_secret)
        # create a incomming SA

    def start_create_outgoing_SA(self, sc_ID, dest):
        shared_secret = self.key_exchange_start(dest)
        if shared_secret != None:
            self.KaY.create_SA(sc_ID, dest, shared_secret, 0)
        else:
            print("Key Exchange Failed")
    
    def end_create_outgoing_SA(self):
        pass

    def create_incoming_SA(self, sc_ID, dest):
        pass

