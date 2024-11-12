import random
from client_control_plane import Client_Control_Plane
from client_data_plane import Client_Data_Plane

class Client():
    def __init__(self, KaY_identifier):
        self.Data_Plane = Client_Data_Plane()
        self.Control_Plane = Client_Control_Plane(self.Data_Plane, KaY_identifier)
        self.Control_Plane.KaY.load_known_hosts()
        self.Data_Plane.start_listener()

    def send_cleartext(self, data, dst_mac, dst_ip, dst_port):
        dst = (dst_mac, dst_ip, dst_port)
        self.Data_Plane.send(data, dst)

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
[5] Send Test Message
[6] Exit
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
                    sc_ID = int(input("Input Secure Channel ID: "))
                    self.Control_Plane.create_outgoing_SA(sc_ID, ("00:00:00:00:00:00", "127.0.0.1", 1337))
                    # target = input("Input target: ")
                elif choice == 3:
                    self.Control_Plane.KaY.print_SCs()
                elif choice == 4:
                    sc_ID = int(input("Input Secure Channel ID: "))
                    self.Control_Plane.KaY.print_SAs(sc_ID)
                elif choice == 5:
                    sc_ID = int(input("In which SC? "))
                    sa_ID = int(input("Via which SA? "))
                    self.Control_Plane.send_via_SA(b"Hello", sc_ID, sa_ID)
                elif choice == 6:
                    off = True
                else:
                    pass
            except Exception as e:
                if e == KeyboardInterrupt:
                    exit(0)
                else:
                    print(f"Unknown option {e}")


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
            client.Data_Plane.send(b'TEST', destination)
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

    #####
    # Probably the way this will work is smth like, suppose we want to send a MACsec message to someone. We first go through the control plane to resolve the address to our SA,
    # Then the cnontrol_plane object will return an SA, we will then use that SA as an input to a Data_Plane object function, send_via_SA. Then we can send our MACsec frames through
    # there
    #####