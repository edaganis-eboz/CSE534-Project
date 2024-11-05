from Crypto.PublicKey import RSA
import threading
import time
from client_control_plane import Client_Control_Plane, Secure_Association, Secure_Channel
from client_data_plane import Client_Data_Plane

class Client():

    def __init__(self):
        self.RSA_key_path = "./client_tools/key.pem"
        self.RSA_key = None
        self.Data_Plane = Client_Data_Plane()
        self.Control_Plane = Client_Control_Plane('Alice')
        try:
            self.load_key()
            print(f"Sucessfully loaded key: {self.RSA_key_path}")
        except:
            print("No RSA keypair found, generating new key")
            self.generate_key()

    def generate_key(self):
        # It would seem that each client has a RSA(2048) Keypair, using that key pair, we can create a CSR, and then a Cert.
        self.RSA_key = RSA.generate(4096)

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


    def send_cleartext(self, data, dst_mac, dst_ip, dst_port):
        dst = (dst_mac, dst_ip, dst_port)
        self.Data_Plane.send_cleartext(data, dst)

    def send_via_SA(self, message, identifiers):
        sc_id, sa_id = identifiers
        SA = self.Control_Plane.KaY.get_SA(sc_id, sa_id)
        self.Data_Plane.send_via_SA(message, SA)






    #######################################
    #         SPECIAL FUNCTIONS           #
    #######################################
        
    def run_test(self, choice):
        if choice == 0:
            self.Control_Plane.KaY.load_known_hosts()
            self.Control_Plane.KaY.print_CA()
            self.Control_Plane.KaY.print_SCs()

            sc_ID = self.Control_Plane.KaY.create_SC()
            self.Control_Plane.KaY.print_SCs()
            sa_ID = self.Control_Plane.KaY.create_SA(sc_ID, self.Control_Plane.KaY.CA_hosts['Bob'])
            self.Control_Plane.KaY.print_SAs(sc_ID)
        else:
            pass


    def interactive(self):
        pass


if __name__ == "__main__":
    client = Client()
    client.run_test(0)
    # sc_identifier = client.Control_Plane.KaY.create_SC()   # We def need better calling conventions

   
    # destination = ("ff:ff:ff:ff:ff:ff", "127.0.0.1", 1234)
    # sa_indentifier = client.Control_Plane.KaY.create_SA(sc_identifier, destination)

    # #test
    # receivingThread = threading.Thread(target=client.Data_Plane.receive_via_SA, daemon=True)
    # receivingThread.start()

    # time.sleep(.5)

    # #client.send_cleartext(b"Hello!\n","ff:ff:ff:ff:ff:ff", "127.0.0.1", 1234)
    # client.send_via_SA(b"Testing\n", (sc_identifier, sa_indentifier))

    # time.sleep(.25)

    #####
    # Probably the way this will work is smth like, suppose we want to send a MACsec message to someone. We first go through the control plane to resolve the address to our SA,
    # Then the cnontrol_plane object will return an SA, we will then use that SA as an input to a Data_Plane object function, send_via_SA. Then we can send our MACsec frames through
    # there
    #####