# This will be the clients. This *should* be written entirely in python
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from scapy.all import Ether, IP, UDP, sendp, send


class MAC_Security_Entity():
    def __init__(self):
        pass

class Client_Data_Plane():
    # SecY is on the data plane
    def __init__(self):
        self.SecY = MAC_Security_Entity()

    def send_via_SC(self, data):
        # This is where we would have Scapy, either a class or a function, that would send our frame with the proper formatting
        # probably a function like, def create_secure_packet(self, dest_mac, dest_ip, dest_port, data)
        # Format would be, (from the paper) MAC_SRC MAC_DST SECTAG |ENCRYPTED DATA| ICV
   
        pass

    def send_cleartext(self, data, src, dst):  
        frame = Ether(src=src[0], dst=dst[0]) / IP(src=src[1], dst=dst[1]) / UDP(dport=dst[2], sport=src[2]) / data
        # packet = IP(dst=dst[1]) / UDP(dport=dst[2], sport=src[2]) / data
        # send(packet)
        try:
            sendp(frame)
            return 0
        except Exception as e:
            return -1

        
    
class Secure_Association():
    def __init__(self):
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
        self.address = ("00:00:00:00:00:00", "127.0.0.1", 1337) # Loopback addr for testing
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
        self.Data_Plane.send_cleartext(data, self.address, dst)

if __name__ == "__main__":
    x = Client()
    x.send_cleartext(b"Hello!\n","ff:ff:ff:ff:ff:ff", "127.0.0.1", 1234)