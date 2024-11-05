from scapy.all import Ether, IP, UDP, sendp, send, Raw
from scapy.sendrecv import sniff
from scapy.utils import hexdump


destination_port = 12345

# Function to handle each received packet
def packet_callback(packet):
    if IP in packet and IP.dst == "127.0.0.1":
        print('A')
    # if UDP in packet:# and packet[UDP].dport == destination_port:
    #     print("Received UDP packet:")
    #     print(f"Source IP: {packet[IP].src}")
    #     print(f"Source Port: {packet[UDP].sport}")
    #     print(f"Destination Port: {packet[UDP].dport}")
    #     print(f"Payload: {packet[Raw] if Raw in packet else 'No payload'}")

# Start sniffing for UDP packets on localhost
print(f"Listening for UDP packets on port {destination_port}...")
sniff(prn=packet_callback, store=0)

