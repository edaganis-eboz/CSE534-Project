# This is our CSE534 project, Ft. Erin O. and Zach D.

### How to Run
First, install all the python requirements in ```requirements.txt```
Clients are both hosts and clients, but for testing purposes, some addresses were hard coded so there is only one way communcation. The default interfaces in FABRIC were ```enp7s0```, so that is reflected in ```client_data_plane.py```

To start the p4 server on a switch, first compile ```toy_router/main.p4``` with the command ```p4c main.p4```. In the topology we used, the command to start the p4 switch is: ```sudo simple_switch -i 0@enp7s0 -i 1@enp8s0 main.json &```

Then run ```chmod +x rules.sh && ./rules.sh``` to populate the match-action tables for the switch

To start the python clients, run ```sudo -E python3 client.py```, first create a secure channel, and then create a secure association within that secure channel. Once that is complete, you can start a latency test that will send 100 messages and get the average latency at the other end.

### ToDo
We never got a python controller to work, the dependencies were so huge, and the documentation so esoteric, it became infeasaible. In theory, the controller would see that a key exchange occurs between two hosts, and automattically at an entry to the sectag match-action table in the p4 switch, instead of having to run a bash script to populate the table. 

### What else is included
```cleartext_ping/``` includes files that test cleartext latency. ```L4_enc/``` includes files that test layer 4 encryption. 
### Run on FABRIC
Follow the Jupyter notebook in the Repo. You will need to SSH into the individual nodes in order to run the latency tests. To install the p4 software on the switch, make sure the line ```switch.upload_file('install_bmv2.sh', 'install_bmv2.sh')``` works properly.