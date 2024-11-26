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

    def nping_via_SA(self, n, identifiers):
        sc_id, sa_id = identifiers
        self.Control_Plane.nping_via_SA(n, sc_id, sa_id)


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
[6] Send Ping
[7] Exit
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
                    self.Control_Plane.create_outgoing_SA(sc_ID, ("00:00:00:00:00:02", "192.168.2.10", 1337)) #alice switch MAC, bob ip
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
                    sc_ID = int(input("In which SC? "))
                    sa_ID = int(input("Via which SA? "))
                    self.nping_via_SA(100, (sc_ID, sa_ID))
                elif choice == 7:
                    off = True
                else:
                    pass
            except Exception as e:
                if e == KeyboardInterrupt:
                    exit(0)
                else:
                    print(f"Unknown option {e}")

if __name__ == "__main__":
    client = Client('Alice')
    
    client.interactive()