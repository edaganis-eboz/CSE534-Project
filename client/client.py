from Crypto.PublicKey import RSA
import threading
import time
import random
from client_control_plane import Client_Control_Plane, Secure_Association, Secure_Channel
from client_data_plane import Client_Data_Plane

class Client():
    def __init__(self, KaY_identifier):
        self.RSA_key_path = "./client_tools/key.pem"
        self.RSA_key = None
        self.Data_Plane = Client_Data_Plane()
        self.Control_Plane = Client_Control_Plane(self.Data_Plane, KaY_identifier)
        try:
            self.load_key()
            print(f"Sucessfully loaded key: {self.RSA_key_path}")
        except:
            print("No RSA keypair found, generating new key")
            self.generate_key()
        self.Control_Plane.KaY.load_known_hosts()
        self.Data_Plane.start_listener()

    def generate_key(self):
        # It would seem that each client has a RSA(2048) Keypair, using that key pair, we can create a CSR, and then a Cert.
        self.RSA_key = RSA.generate(4096)
        self.Control_Plane.RSA_Key = self.RSA_key
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
            self.Control_Plane.RSA_Key = self.RSA_key

    def send_cleartext(self, data, dst_mac, dst_ip, dst_port):
        dst = (dst_mac, dst_ip, dst_port)
        self.Data_Plane.send_cleartext(data, dst)

    def send_via_SA(self, message, identifiers):
        sc_id, sa_id = identifiers
        SA = self.Control_Plane.KaY.get_SA(sc_id, sa_id)
        self.Data_Plane.send_via_SA(message, SA)

    def interactive(self):
        off = False
        options = """
Select an Option:
[0] List Hosts in Connectivity Association
[1] Create Secure Channel
[2] Create Secure Association
[3] List Secure Channels
[4] List Secure Associations
[5] Exit
        """
        while (not off):
            print(options)
            try:
                choice = int(input(">"))
                if choice == 0:
                    self.Control_Plane.KaY.print_CA()
                elif choice == 1:
                    sc_ID = self.Control_Plane.KaY.create_SC()
                    print(f"Secure Channel created with ID: {sc_ID}")
                elif choice == 2:
                    self.Data_Plane.send_cleartext(b"Hello", ("00:00:00:00:00:00", "127.0.0.1", 1337))
                    # sc_ID = input("Input Secure Channel ID: ")
                    # target = input("Input target: ")
                    # self.Control_Plane.create_outgoing_SA(sc_ID, "Bob")
                elif choice == 3:
                    self.Control_Plane.KaY.print_SCs()
                elif choice == 4:
                    sc_ID = input("Input Secure Channel ID: ")
                    self.Control_Plane.KaY.print_SAs(sc_ID)
                elif choice == 5:
                    off = True
                else:
                    pass
            except Exception as e:
                if e == KeyboardInterrupt:
                    exit(0)
                else:
                    print("Unknown option")


def run_test(client: Client, choice):
    if choice == 0:
        client.Control_Plane.KaY.load_known_hosts()
        client.Control_Plane.KaY.print_CA()
        client.Control_Plane.KaY.print_SCs()
        sc_ID = client.Control_Plane.KaY.create_SC()
        client.Control_Plane.KaY.print_SCs()
        sa_ID = client.Control_Plane.KaY.create_SA(sc_ID, client.Control_Plane.KaY.CA_hosts['Bob'])
        client.Control_Plane.KaY.print_SAs(sc_ID)
    elif choice == 1:
        listen_or_send = int(input("Options:\n(0) Listen\n(1) Send\n")) % 2
        if listen_or_send: # 1
            destination_port = int(input("Destination Port? "))
            destination = ("ff:ff:ff:ff:ff:ff", "127.0.0.1", destination_port)
            client.Data_Plane.send_cleartext(b'TEST', destination)
        else:
            port_num = random.randint(10000, 65535)
            mac, ip, _ = client.Data_Plane.src
            client.Data_Plane.src = (mac, ip, port_num)
            client.Data_Plane.cleartext_listen()
    elif choice == 2:
        client.Data_Plane.start_listener()
        #client.Control_Plane.create_SA()
    else:
        pass

if __name__ == "__main__":
    client = Client('Alice')
    
    client.interactive()
    #run_test(client, 2)
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