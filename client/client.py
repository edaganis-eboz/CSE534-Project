# This will be the clients. This *should* be written entirely in python
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from scapy.all import Ether, IP, UDP, sendp, send, Raw
from scapy.utils import hexdump


class MAC_Security_Entity():
    def __init__(self):
        pass

class Client_Data_Plane():
    # SecY is on the data plane
    def __init__(self):
        self.src = ("00:00:00:00:00:00", "127.0.0.1", 1337)
        self.SecY = MAC_Security_Entity()

    def send_via_SA(self, data, SA):
        # This is where we would have Scapy, either a class or a function, that would send our frame with the proper formatting
        # Format would be, (from the paper) MAC_SRC MAC_DST SECTAG |ENCRYPTED DATA| ICV
        # Use SA.cipher, to encrypt and do the ICV calculation and what not, SA.cipher is our Secure Assocation Key (SAK) for all intents and purposes
        frame = Ether(src=self.src[0], dst=SA.destination[0])
        sectag = b"SECTAG"

        ciphertext, tag = SA.cipher.encrypt_and_digest(data)

        icv = tag

        macSecFrame = frame / Raw(load=sectag) / Raw(load=ciphertext) / Raw(load=icv)

        try:
            sendp(macSecFrame)
            print(f"MACsec frame: {macSecFrame}")
            if Raw in macSecFrame:
                print("Raw Payload:")
                frame.show()  # Display the entire packet
                hexdump(macSecFrame)  # Print the raw data in hex format
            return 0
        except Exception as e:
            print(f"Error: {e}")
            return -1

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
    def __init__(self):
        self.destination = ("MAC_ADDR", "IP_ADDR", "PORT")
        self.key = b'0123456789ABCDEF'
        self.cipher = AES.new(self.key, AES.MODE_GCM)

class Secure_Channel():
    def __init__(self):
        pass

    def create_SA(self, dest):
        pass

class Key_Agreement_Entity():
    def __init__(self):
        self.key_ring = None

    def MKA(self):
        pass

    def create_SC(self, dest):
        pass

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
    SA = Secure_Association()
    SA.destination = ("ff:ff:ff:ff:ff:ff", "127.0.0.1", 1234)
    client.send_cleartext(b"Hello!\n","ff:ff:ff:ff:ff:ff", "127.0.0.1", 1234)
    client.Data_Plane.send_via_SA(b"test\n", SA)


    #####
    # Probably the way this will work is smth like, suppose we want to send a MACsec message to someone. We first go through the control plane to resolve the address to our SA,
    # Then the cnontrol_plane object will return an SA, we will then use that SA as an input to a Data_Plane object function, send_via_SA. Then we can send our MACsec frames through
    # there
    #####