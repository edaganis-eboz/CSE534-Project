from scapy.all import Ether, IP, UDP, sendp, Raw
from scapy.sendrecv import sniff
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import threading
import queue
from collections import deque
import hashlib

from client_control_plane import Secure_Channel, Secure_Association # I really dont like this

class MAC_Security_Entity():
    def __init__(self):
        pass

    def send_via_SA(self, src, data, SA):

        cipher = AES.new(SA.key, AES.MODE_GCM) # TODO Not sure how I feel about this, do once only?

        frame = Ether(src=src[0], dst=SA.destination[0])
        sectag = self.create_sectag(SA)
        serialized_sectag = self.serialize_sectag(sectag)

        ciphertext, icv = cipher.encrypt_and_digest(data)

        iv = cipher.nonce

        macSecFrame = frame / Raw(load=serialized_sectag) / Raw(load=iv) / Raw(load=ciphertext) / Raw(load=icv)
        # print("\nciphertext sent: ", ciphertext, "\n")

        return macSecFrame
        
    def create_sectag(self, SA):
        sectag = {'sc_ID': SA.sc_identifier, 'sa_ID': SA.sa_identifier, 're-keying': False}
        return sectag
    
    def serialize_sectag(self, sectag):
        #print("SA_ID in serialize: ", sectag['sa_ID'])
        sc_identifier = sectag['sc_ID'].to_bytes(2, 'big')
        sa_identifier = sectag['sa_ID'].to_bytes(2, 'big')

        #print("sa_identifier in serialize: ",int.from_bytes(sa_identifier, 'big'))

        rekeying_flag = b'\x01' if sectag['re-keying'] else b'\x00'

        serialized_sectag = sc_identifier+sa_identifier+rekeying_flag

        return(serialized_sectag)

    def receive_via_SA(self, frame):
        eth_frame = frame[Ether]
        raw_payload = frame[Raw].load
        sectag_size = 5
        sectag = raw_payload[:sectag_size]
        iv = raw_payload[sectag_size:sectag_size+16]
        ciphertext = raw_payload[sectag_size+16:-16]
        icv = raw_payload[-16:]
        sectag_deserialized = self.deserialized_sectag(sectag)
        
        return (ciphertext, icv, sectag_deserialized, iv)

    def deserialized_sectag(self, sectag):
        sc_ID = int.from_bytes(sectag[:2], 'big')
        sa_ID = int.from_bytes(sectag[2:4], 'big')
        #print("sa_ID in deserialize: ", sa_ID)
        rekeying = True if sectag[4] == 1 else False

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
    def __init__(self):
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
        def handle(frame):
            if not self.is_duplicate(frame):
                if Ether in frame and Raw in frame: # TODO somehow make this only sniff our packets, original headers?
                    self.queue.put(frame)

        try:
            print(f"Listening...")
            sniff(iface="lo", prn=handle, store=0)
        except Exception as e:
            print(f"Sniffing failed: {e}")


class Client_Data_Plane():
    # SecY is on the data plane
    def __init__(self):
        self.src = ("00:00:00:00:00:00", "127.0.0.1", 1337)
        self.listener = Listener()
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
                sendp(frame, iface="lo", verbose=False) # TODO: change iface when in production
                return 0
            except Exception as e:
                print(f"Sendp failed: {e}")
                return -1
        else:
            frame = self.SecY.send_via_SA(self.src, data, secure_association)
            # frame.show()
            sendp(frame, iface="lo", verbose=False) # TODO: change iface when in production
            
    



        