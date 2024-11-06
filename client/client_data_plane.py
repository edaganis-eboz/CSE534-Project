from scapy.all import Ether, IP, UDP, sendp, send, Raw
from scapy.sendrecv import sniff
from scapy.utils import hexdump
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import threading
import queue

from client_control_plane import Secure_Channel, Secure_Association # I really dont like this

class MAC_Security_Entity():
    def __init__(self):
        pass

    def send_via_SA(self, data, SA):

        # This is where we would have Scapy, either a class or a function, that would send our frame with the proper formatting
        # Format would be, (from the paper) MAC_SRC MAC_DST SECTAG |ENCRYPTED DATA| ICV
        # Use SA.cipher, to encrypt and do the ICV calculation and what not, SA.cipher is our Secure Assocation Key (SAK) for all intents and purposes
        
        SA.cipher = AES.new(SA.key, AES.MODE_GCM)

        frame = Ether(src=self.src[0], dst=SA.destination[0])
        sectag = self.create_sectag(SA)
        serialized_sectag = self.serialize_sectag(sectag)

        ciphertext, icv = SA.cipher.encrypt_and_digest(data)

        iv = SA.cipher.nonce

        macSecFrame = frame / Raw(load=serialized_sectag) / Raw(load=iv) / Raw(load=ciphertext) / Raw(load=icv)

        print("\nciphertext sent: ", ciphertext, "\n")

        try:
            sendp(macSecFrame)
            print(f"MACsec frame Sent: {macSecFrame}")
            if Raw in macSecFrame:
                # print("Raw Payload:")
                # hexdump(macSecFrame)  # Print the raw data in hex format
                return 0
        except Exception as e:
            print(f"Error: {e}")
            return -1
    
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

    def receive_via_SA(self):
        def packet_handler(packet):
            if Ether in packet and Raw in packet:
                try:
                    #print(f"MACsec frame Received: {packet}")
                    if Raw in packet:
                        # print("Raw Payload:")
                        # hexdump(packet)  # Print the raw data in hex format
                        pass
                except Exception as e:
                    print(f"Error: {e}")
                    return -1

                eth_frame = packet[Ether]
                raw_payload = packet[Raw].load

                sectag_size = 5
                sectag = raw_payload[:sectag_size]
                iv = raw_payload[sectag_size:sectag_size+16]
                ciphertext = raw_payload[sectag_size+16:-16]
                icv = raw_payload[-16:]
                print("\nciphertext received: ", ciphertext, "\n")

                sectag_deserialized = self.deserialized_sectag(sectag)

                data = self.decrypt_data(ciphertext, icv, sectag_deserialized['sa_ID'], iv)

                print("Received data: ", data, "End of data")

        try:
            sniff(prn=packet_handler, store=0)
        except Exception as e:
            print(f"Sniffing failed: {e}")

    def deserialized_sectag(self, sectag):
        sc_ID = int.from_bytes(sectag[:2], 'big')
        sa_ID = int.from_bytes(sectag[2:4], 'big')
        #print("sa_ID in deserialize: ", sa_ID)
        rekeying = True if sectag[4] == 1 else False

        plain_sectag = {'sc_ID': sc_ID, 'sa_ID': sa_ID,'re-keying': rekeying}

        return plain_sectag
    def decrypt_data(self, ciphertext, icv, sa_ID, iv):
        SA = self.get_secure_association(sa_ID)

        if SA is None:
            print(f"No Secure Association found for SA ID: {sa_ID}")
            return None

        cipher = AES.new(SA.key, AES.MODE_GCM, nonce=iv)

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, icv)
            return plaintext
        except ValueError:
            print("Decryption failed: incorrect tag (ICV)")
            return None

    def get_secure_association(self, sa_ID):
        for sa in self.secure_association:
            if sa.sa_identifier == sa_ID:
                return sa

        print(f"No Secure Association found for SA ID: {sa_ID}")  # Debug message
        return None  # Explicitly return None if not found

    def add_secure_association(self, sc_ID, sa_ID, dest):
        new_SA = Secure_Association(sa_ID, dest)
        self.secure_association.append(new_SA)

class Cleartext_Handler():
    def __init__(self):
        self.queue = queue.Queue()
        self.home_address = None
    
    @staticmethod
    def send_cleartext(src, data, dst):  
        frame = Ether(src=src[0], dst=dst[0]) / IP(src=src[1], dst=dst[1]) / UDP(dport=dst[2], sport=src[2]) / data
        try:
            sendp(frame, iface="lo") # TODO: change iface when in production
            return 0
        except Exception as e:
            return -1

    def cleartext_listen(self):
        def handle(frame):
            if UDP in frame and frame[UDP].dport == self.src[2]:
                print("Received UDP packet:")
                print(f"Source IP: {frame[IP].src}")
                print(f"Source Port: {frame[UDP].sport}")
                print(f"Destination Port: {frame[UDP].dport}")
                print(f"Payload: {frame[Raw] if Raw in frame else 'No payload'}")

        try:
            print(f"Listening for UDP packets on port {self.src[2]}...")
            sniff(iface="lo", prn=handle, store=0)
        except Exception as e:
            print(f"Sniffing failed: {e}")


class Client_Data_Plane():
    # SecY is on the data plane
    def __init__(self):
        self.src = ("00:00:00:00:00:00", "127.0.0.1", 1337)
        self.cleartext_handler = Cleartext_Handler()
        self.SecY = MAC_Security_Entity()
        try:
            self.cleartext_handler.start_listen()
        except Exception as e:
            print("Cleartext listener failed to start....")

    def send_cleartext(self, data, dst):
        self.cleartext_handler.send_cleartext(self.src, data, dst)

    



        