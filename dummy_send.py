from scapy.all import Ether, IP, UDP, sendp, send, Raw
from scapy.sendrecv import sniff
from scapy.utils import hexdump


packet = IP(src="127.0.0.1", dst="127.0.0.1") / UDP(dport=12345, sport=1337) / b'Hello'
print(packet.summary())
send(packet)