from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from scapy.all import Ether, IP, UDP, sendp, Raw
from random import randint
from os import urandom
from util import *
import queue
import threading
import time


class Key_Agreement_Entity():
    def __init__(self, identifier):
        self.RSA_key_path = "./client_tools/key.pem"
        self.RSA_key = None
    
        self.KaY_indentifier = identifier
        self.CA_hosts = {}
        self.secure_channels = {}
        self.secure_channels[-1] = Secure_Channel(-1) # Special Channel for incomming SA's
        try:
            self.load_key()
            print(f"Sucessfully loaded key: {self.RSA_key_path}")
        except:
            print("No RSA keypair found, generating new key")
            self.generate_key()


    def generate_key(self):
        # It would seem that each client has a RSA(2048) Keypair, using that key pair, we can create a CSR, and then a Cert.
        self.RSA_key = RSA.generate(2048)
        # Save the keypairs
        try:
            with open(self.RSA_key_path, "wb") as f:
                data = self.RSA_key.export_key()
                f.write(data)
            print(f"Successfully generated key and saved to {self.RSA_key_path}")
        except:
            print("Key generation failed! Exiting...")
            exit(1)

    def load_key(self):
        with open(self.RSA_key_path, "rb") as f:
            data = f.read()
            self.RSA_key = RSA.import_key(data)

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
    
    def create_SA(self, sa_ID, sc_ID, dest, key):
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
        self.RSA_Key = self.KaY.RSA_key
        
        self.nping_total: float = 0.0
        self.nping_count: int = 0
        # Threading Stuff
        self.lock = threading.Lock()
        self.running = True
        self.data_plane_listen = threading.Thread(target=self.get_traffic_from_data_plane, daemon=True)
        self.data_plane_listen.start()
    
    @staticmethod
    def get_src_info(frame):
        eth = frame.getlayer(Ether)
        ip = frame.getlayer(IP)
    
        if eth and ip:
            src_eth = eth.src        
            src_ip = ip.src          

            return (src_eth, src_ip)
        else:
            return None 
    
    
    def process_frame(self, frame):
        with self.lock:
            # frame.show()
            if KE_Header in frame:
                try:
                    stage = KE_Protocol_Messages(frame[KE_Header].stage)
                    if stage == KE_Protocol_Messages.SA_KE_REQUEST:
                        self.key_exchange_accept(frame)
                    elif stage == KE_Protocol_Messages.SA_KE_ACCEPT:
                        self.key_exchange_send_pubkey(frame)
                    elif stage == KE_Protocol_Messages.SA_KE_PUBKEY:
                        self.key_exchange_send_encrypted_secret(frame)
                    elif stage == KE_Protocol_Messages.SA_KE_SECRET:
                        self.key_exchange_create_outgoing(frame)
                    else:
                        print(f"Message: {stage}")
                except Exception as e:
                    print(f"AAAAAAAAAAAA {e}")
            elif Raw in frame:
                try:
                    ciphertext, icv, sectag_deserialized, iv = self.Data_Plane.SecY.receive_via_SA(frame)
                    sc_id = -1
                    sa_id = sectag_deserialized['sa_ID']
                    secure_association = self.KaY.secure_channels[sc_id].associations[sa_id]
                    plaintext = self.Data_Plane.SecY.decrypt_data(ciphertext, icv, secure_association.key, iv)
                    try:
                        ping = PING_Messages(plaintext[:12])
                        self.receive_nping(plaintext)
                    except ValueError:
                        print(f"Recieved Decrypted Plaintext: {plaintext}")
                except Exception as e:
                    print(f"Decryption Failed: {e}")



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
            sa_id = 11111 # Hard coding sa_id to make this easier
            # sa_id = randint(10000, 65535) # TODO This rand int stuff needs to check if there is no SA/SC with the same identifier
            self.key_exchange_start(sc_id, sa_id, dst)
    
    def send_via_SA(self, message, sc_id, sa_id):
        secure_association = self.KaY.secure_channels[sc_id].associations[sa_id]
        self.Data_Plane.send(message, None, secure_association=secure_association)
    
    def nping_via_SA(self, n, sc_id, sa_id):
        secure_association = self.KaY.secure_channels[sc_id].associations[sa_id]
        count: int = 0
        while count < n:
            print(f'nping_count:{count}')
            t = str(time.time()).encode()
            message = PING_Messages.PING_REQUEST.value + t
            self.Data_Plane.send(message, None, secure_association=secure_association)
            count += 1
            time.sleep(0.3)

    def receive_nping(self, plaintext):
        ping = PING_Messages(plaintext[:12])
        if ping == PING_Messages.PING_REQUEST:
            t1 = plaintext[12:30]
            t2 = time.time()
            one_way_trip_time = t2 - float(t1)
            print(f"Ping Received! Trip Time: {one_way_trip_time}")
            self.nping_total += one_way_trip_time
            self.nping_count += 1
            if self.nping_count % 100 == 0:
                print(f"Average latency: {self.nping_total / self.nping_count}")
            # TODO send ping reply
        elif ping == PING_Messages.PING_REPLY:
            # TODO check if there is an outgoing SA for the host who send the ping
            pass
        else:
            print("Something went wrong with ping")

    # TODO This needs to be in try except blocks as well
    def key_exchange_start(self, sc_id, sa_id, dst): # I dont know how I feel about this, this is done in plaintext, so it should be okay to be outisde of KaY
        header = KE_Header(stage=KE_Protocol_Messages.SA_KE_REQUEST.value,
                           system_identifier=sc_id,
                           sa_identifier=sa_id
                           )
        message = header
        self.Data_Plane.send(message, dst)

    def key_exchange_accept(self, frame):
        return_addr = self.get_src_info(frame)
        sc_id = frame[KE_Header].system_identifier
        sa_id = frame[KE_Header].sa_identifier
        header = KE_Header(stage=KE_Protocol_Messages.SA_KE_ACCEPT.value,
                           system_identifier=sc_id,
                           sa_identifier=sa_id
                           )
        message = header
        self.Data_Plane.send(message, return_addr)
        
    def key_exchange_send_pubkey(self, frame):
        return_addr = self.get_src_info(frame)
        sc_id = frame[KE_Header].system_identifier
        sa_id = frame[KE_Header].sa_identifier
        try:
            # assert self.RSA_Key != None
            header = KE_Header(stage=KE_Protocol_Messages.SA_KE_PUBKEY.value,
                           system_identifier=sc_id,
                           sa_identifier=sa_id
                           )
            key_message = self.RSA_Key.publickey().export_key(format='PEM')
            message = header / Raw(key_message)
            self.Data_Plane.send(message, return_addr)
        except AssertionError:
            print("No key")

    def key_exchange_send_encrypted_secret(self, frame):
        return_addr = self.get_src_info(frame)
        sc_id = frame[KE_Header].system_identifier
        sa_id = frame[KE_Header].sa_identifier

        pubkey = RSA.import_key(frame[Raw].load)
        secret = urandom(32)
        cipher = PKCS1_OAEP.new(pubkey)
        encrypted_secret = cipher.encrypt(secret)

        header = KE_Header(stage=KE_Protocol_Messages.SA_KE_SECRET.value,
                           system_identifier=sc_id,
                           sa_identifier=sa_id
                           )

        message = header / Raw(encrypted_secret)
        self.Data_Plane.send(message, return_addr)
        
        # create a incomming SA
        self.KaY.create_SA(int(sa_id), -1, return_addr, secret)

    def key_exchange_create_outgoing(self, frame):
        return_addr = self.get_src_info(frame)
        sc_id = frame[KE_Header].system_identifier
        sa_id = frame[KE_Header].sa_identifier
        encrypted_secret = frame[Raw].load
        cipher = PKCS1_OAEP.new(self.RSA_Key)
        shared_secret = cipher.decrypt(encrypted_secret)
        if shared_secret != None:
            self.KaY.create_SA(sa_id, sc_id, return_addr, shared_secret)
        else:
            print("Key Exchange Failed")


