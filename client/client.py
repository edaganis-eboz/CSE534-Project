# This will be the clients. This *should* be written entirely in python
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES


class Client_Data_Plane():
    # SecY is on the data plane
    def __init__(self):
        pass

class Client_Control_Plane():
    # KaY is on the control plane
    def __init__(self):
        pass

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
        with open(self.RSA_key_path, "wb") as f:
            data = self.RSA_key.export_key()
            f.write(data)

        print(f"Successfully generated key and saved to {self.RSA_key_path}")


    def load_key(self):
        with open(self.RSA_key_path, "rb") as f:
            data = f.read()
            self.RSA_key = RSA.import_key(data)


if __name__ == "__main__":
    x = Client()
