# This is our CSE534 project, Ft. Erin O. and Zach D.

## TODO

### Controllers

Controllers are in charge of some of the keys and more importantly are in charge of routing.

### Hosts

Hosts are the hosts, they need to send packets in the correct ways and have proper key generation. For testing purposes I would like to quickly add and remove hosts. Docker might be a must here



#### Goals for after meeting 1

Code hosts that properly generate keys, and be able to save them to file. Hosts with already created certs should be able to load them back up. GRPC? Figure out what the purpose of that was in the orignal paper. We want the hosts to use SCAPY to create the MACsec packets. It is our belief that if we do this, we will get a better understanding of the packet structure and modify it easier if need be. We want the hosts to be able to communicate. After meeting 2 we will introduce the local controllers.
- Key generation/Saving
- Structure of MACsec packets
- Interclient communcation

