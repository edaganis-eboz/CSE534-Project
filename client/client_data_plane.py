from scapy.all import Ether, IP, UDP, sendp, Raw, ICMP, get_if_addr, get_if_hwaddr
from scapy.sendrecv import sniff
from Crypto.Cipher import AES
import threading
import queue
from collections import deque
import hashlib
from util import SecTag
import socket
# from client_control_plane import Secure_Channel, Secure_Association # I really dont like this

class MAC_Security_Entity():
    def __init__(self):
        pass

    def send_via_SA(self, src, data, SA):
        MACSEC_ETHERTYPE = 0x0801
        cipher = AES.new(SA.key, AES.MODE_GCM) # TODO Not sure how I feel about this, do once only?

        frame = Ether(src=src[0], dst=SA.destination[0], type=MACSEC_ETHERTYPE)
        sectag = self.create_sectag(SA)
        sectag_header: SecTag = self.serialize_sectag(sectag)

        ciphertext, icv = cipher.encrypt_and_digest(data)

        iv = cipher.nonce
        payload = iv + ciphertext + icv

        macSecFrame = frame / sectag_header / Raw(load=payload)
        # print("\nciphertext sent: ", ciphertext, "\n")

        return macSecFrame
        
    def create_sectag(self, SA):
        sectag = {'sc_ID': SA.sc_identifier, 'sa_ID': SA.sa_identifier, 're-keying': False}
        return sectag
    
    def serialize_sectag(self, sectag):
        sc_identifier = sectag['sc_ID']
        sa_identifier = sectag['sa_ID']
        rekeying_flag = 1 if sectag['re-keying'] else 0

        sectag_header = SecTag(system_identifier=sc_identifier, sa_identifier=sa_identifier, rekey_flag=rekeying_flag)

        return sectag_header

    def receive_via_SA(self, frame):
        IV_LENGTH: int = 16
        ICV_LENGTH: int = 16
        sectag_header = frame[SecTag]
        raw_payload = frame[Raw].load
        iv = raw_payload[:IV_LENGTH]
        ciphertext = raw_payload[IV_LENGTH:-ICV_LENGTH]
        icv = raw_payload[-ICV_LENGTH:]
        sectag_deserialized = self.deserialized_sectag(sectag_header)
        
        return (ciphertext, icv, sectag_deserialized, iv)

    def deserialized_sectag(self, sectag_header: SecTag):
        sc_ID = sectag_header.system_identifier
        sa_ID = sectag_header.sa_identifier
        #print("sa_ID in deserialize: ", sa_ID)
        rekeying = True if sectag_header.rekey_flag == 1 else False

        plain_sectag = {'sc_ID': sc_ID, 'sa_ID': sa_ID,'re-keying': rekeying}

        return plain_sectag
    def decrypt_data(self, ciphertext, icv, key, iv):
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, icv)
            return plaintext
        except ValueError:
            print("Decryption failed: incorrect tag (ICV)")
            return None

class Listener():
    def __init__(self, src, iface):
        self.src = src
        self.iface = iface
        self.queue = queue.Queue()
        self.recent_packets = deque(maxlen=10)

    def is_duplicate(self, packet):
        packet_hash = hashlib.md5(bytes(packet)).hexdigest()

        if packet_hash in self.recent_packets:
            return True
        self.recent_packets.append(packet_hash)
        return False
    
    def start(self):
        listener_thread = threading.Thread(target=self.listen, daemon=True)
        listener_thread.daemon = True
        listener_thread.start()
        return listener_thread.ident

    def listen(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((get_if_addr(self.iface),1337)) # we need this udp port to be open just so the kernel doesnt say it isnt open
        
        def handle(frame):
            if not self.is_duplicate(frame):
                if Ether in frame and Raw in frame and ICMP not in frame: # TODO somehow make this only sniff our packets, original headers?
                    if frame[Ether].src != self.src[0]:
                        self.queue.put(frame)

        try:
            print(f"Listening...")
            sniff(iface=self.iface, prn=handle, store=0) 
        except Exception as e:
            print(f"Sniffing failed: {e}")


class Client_Data_Plane():
    # SecY is on the data plane
    def __init__(self):
        self.iface = "enp7s0"
        self.src = (get_if_hwaddr(self.iface), get_if_addr(self.iface), 1337)
        self.listener = Listener(self.src, self.iface)
        self.SecY = MAC_Security_Entity()
        
    def start_listener(self):
        try:
            self.listener.start()
        except Exception as e:
            print("Listener failed to start....")
            print(f"{e}")

    def send(self, data, dst, secure_association = None):
        if secure_association == None:  
            frame = Ether(src=self.src[0], dst=dst[0]) / IP(src=self.src[1], dst=dst[1]) / UDP(dport=dst[2], sport=self.src[2]) / data
            try:
                # print(f"Data: {data}")
                sendp(frame, iface=self.iface, verbose=False) 
                return 0
            except Exception as e:
                print(f"Sendp failed: {e}")
                return -1
        else:
            frame = self.SecY.send_via_SA(self.src, data, secure_association)
            # frame.show()
            sendp(frame, iface=self.iface, verbose=False) 
            
    



        