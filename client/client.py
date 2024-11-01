# This will be the clients. This *should* be written entirely in python
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from scapy.all import Ether, IP, UDP, sendp, send, Raw
from scapy.sendrecv import sniff
from scapy.utils import hexdump
import threading
import time


class MAC_Security_Entity():
    def __init__(self):
        pass

class Client_Data_Plane():
    # SecY is on the data plane
    def __init__(self):
        self.src = ("00:00:00:00:00:00", "127.0.0.1", 1337)
        self.SecY = MAC_Security_Entity()
        self.secure_association = []

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
        sectag = {'sc_ID': SC.sc_identifier, 'sa_ID': SA.sa_identifier, 're-keying': False}
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

    def send_cleartext(self, data, dst):  
        frame = Ether(src=self.src[0], dst=dst[0]) / IP(src=self.src[1], dst=dst[1]) / UDP(dport=dst[2], sport=self.src[2]) / data
        # packet = IP(dst=dst[1]) / UDP(dport=dst[2], sport=src[2]) / data
        # send(packet)
        try:
            sendp(frame)
            return 0
        except Exception as e:
            return -1
    
class Secure_Association():
    def __init__(self, sa_ID, dest):
        self.sa_identifier = sa_ID #placeholder
        self.destination = dest #("MAC_ADDR", "IP_ADDR", "PORT")
        self.key = b'0123456789ABCDEF'
        self.cipher = None

class Secure_Channel():
    def __init__(self, sc_ID):
        self.sc_identifier = sc_ID #placeholder
        self.associations = {}

    def create_SA(self, sa_ID, dest):
        sa = Secure_Association(sa_ID, dest)
        self.associations[sa_ID] = sa
        return sa

    def get_SA(self, sa_ID):
        return self.associations.get(sa_ID)

class Key_Agreement_Entity():
    def __init__(self):
        self.key_ring = None
        self.secure_channels = {}

    def MKA(self):
        pass

    def create_SC(self, sc_ID):
        sc = Secure_Channel(sc_ID)
        self.secure_channels[sc_ID] = sc
        return sc

    def get_SC(self, sc_ID):
        return self.secure_channels.get(sc_ID)

class Client_Control_Plane():
    # KaY is on the control plane
    def __init__(self):
        self.KaY = Key_Agreement_Entity()


class Client():

    def __init__(self):
        self.RSA_key_path = "./client_tools/key.pem"
        self.RSA_key = None
        self.Data_Plane = Client_Data_Plane()
        self.Control_Plane = Client_Control_Plane()
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

    def create_CSR(self):
        # For the sake of simplicity, I'm going to define my own Certificate Signing Request and Certificate format
        pass


    def DEBUG_self_sign_cert(self):
        pass


    def load_key(self):
        with open(self.RSA_key_path, "rb") as f:
            data = f.read()
            self.RSA_key = RSA.import_key(data)


    def send_cleartext(self, data, dst_mac, dst_ip, dst_port):
        dst = (dst_mac, dst_ip, dst_port)
        self.Data_Plane.send_cleartext(data, dst)

if __name__ == "__main__":
    client = Client()
    sc_identifier = 1111
    SC = client.Control_Plane.KaY.create_SC(sc_identifier)

    sa_identifier = 2222
    destination = ("ff:ff:ff:ff:ff:ff", "127.0.0.1", 1234)
    SA = SC.create_SA(sa_identifier, destination)

    client.Data_Plane.add_secure_association(sc_identifier, sa_identifier, destination)

    #test
    receivingThread = threading.Thread(target=client.Data_Plane.receive_via_SA, daemon=True)
    receivingThread.start()

    time.sleep(.5)

    #client.send_cleartext(b"Hello!\n","ff:ff:ff:ff:ff:ff", "127.0.0.1", 1234)
    client.Data_Plane.send_via_SA(b"Testing\n", SA)

    time.sleep(.25)

    #####
    # Probably the way this will work is smth like, suppose we want to send a MACsec message to someone. We first go through the control plane to resolve the address to our SA,
    # Then the cnontrol_plane object will return an SA, we will then use that SA as an input to a Data_Plane object function, send_via_SA. Then we can send our MACsec frames through
    # there
    #####