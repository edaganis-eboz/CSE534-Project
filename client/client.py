# This will be the clients. This *should* be written entirely in python
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15



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
        """
        What MACsec Protects:

MACsec encrypts and protects most of the Ethernet frame's payload, including:

    The payload (data) portion of the Ethernet frame. I.e. IP header & TCP header
    Some of the Layer 2 headers, like the EtherType.
    The optional VLAN tags (if present in the frame).

What MACsec Does Not Encrypt:

    MAC addresses: The source and destination MAC addresses remain in plaintext because they are essential for Layer 2 switching and routing.
    SecTAG (Security Tag): This is a special tag added to the frame to carry MACsec-related information like the Secure Channel Identifier (SCI) and packet numbering for replay protection. The SecTAG is also sent in the clear.
    The integrity check value (ICV) that ensures data integrity.
           """
        pass
class Secure_Association():
    """
    Afterwards,
it (KaY) creates and maintains secure channels (SCs) between the
MACsec peers that are used by the SecY to transmit and re-
ceive network packets. SCs are sender-specific, unidirectional,
point-to-multipoint channels. Each SC holds multiple secure
associations (SAs) that have a secure association key (SAK)
used for encrypting, decrypting, and authenticating packets
    """
    def __init__(self):
        self.key = b'0123456789ABCDEF'
        self.cipher = AES.new(self.key, AES.MODE_GCM)

class Key_Agreement_Entity():
    def __init__(self):
        pass

    def MKA(self):
        pass

    def create_SC(self, dest):
        pass

    def create_SA(self, dest):
        pass


class Client_Control_Plane():
    # KaY is on the control plane
    def __init__(self):
        self.KaY = Key_Agreement_Entity()


class Client():

    def __init__(self):
        self.RSA_key_path = "./client_tools/key.pem"
        self.RSA_key = None
        self.Data_plane = Client_Data_Plane()
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


if __name__ == "__main__":
    x = Client()
