# import sys
# sys.path.insert(0, '/usr/lib/python3/dist-packages')

import grpc
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc


def main():
    GRPC_SERVER_ADDR = "0.0.0.0:9559"
    channel = grpc.insecure_channel(GRPC_SERVER_ADDR)
    stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)

    
    # Define a generator to keep the stream open (empty requests for now)
    def stream_generator():
        while True:
            yield p4runtime_pb2.StreamMessageRequest()
    
    stream = stub.StreamChannel(stream_generator())

    def listen_to_packets():
        print("Listening for incoming packets...")
        try:
            for response in stream:
                print('A')
                if response.HasField("packet"):
                    # Check if it's an IP packet based on Ethernet Type
                    eth_type = int.from_bytes(response.packet.metadata[0].metadata, "big")
                    if eth_type == 0x0800:  # 0x0800 is the EtherType for IPv4
                        print("IP packet received")
        except grpc.RpcError as e:
            print(f"gRPC error while listening to packets: {e.code()} - {e.details()}")

    try:
        listen_to_packets()
    finally:
        channel.close()


if __name__ == "__main__":
    main()