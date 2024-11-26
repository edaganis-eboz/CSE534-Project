from scapy.all import Ether, Raw, sendp
from util import SecTag, ICV


def main():
    message = b'Hello'
    frame = Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00") / SecTag(system_identifier=10, port_number=5, sa_identifier=12) / Raw(message) / ICV()
    frame.show()
    sendp(frame, iface='localhost')

if __name__ == "__main__":
    main()