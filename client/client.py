# This will be the clients. This *should* be written entirely in python
from Crypto.PublicKey import RSA

class Client():
    
    def __init__(self):
        self.RSA_key_path = "./client_tools/key.pem"
        self.RSA_key = None
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
        with open(self.RSA_key_path, "wb") as f:
            data = self.RSA_key.export_key()
            f.write(data)

        print(f"Successfully generated key and saved to {self.RSA_key_path}")


    def load_key(self):
        with open(self.RSA_key_path, "rb") as f:
            data = f.read()
            self.RSA_key = RSA.import_key(data)

    def create_cipher(self):
        pass


    def create_secure_channel(self, cipher):
        # This is either going to be in the clients or in the switches
        pass

if __name__ == "__main__":
    x = Client()
