import grpc
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc

def connect_to_switch(address):
    """Establish a gRPC channel to the switch and return the P4Runtime stub."""
    channel = grpc.insecure_channel(address)
    stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)
    return stub, channel

def process_metadata(metadata):
    # Extract the field_info value (example)
    field_info = int(metadata[0].struct.field_info)
    print(f"Extracted Header Info: {field_info}")
    return field_info

def main():
    # Address of the switch's P4Runtime server (change as needed)
    switch_address = "127.0.0.1:9559"
    device_id = 1

    # Connect to the switch
    stub, channel = connect_to_switch(switch_address)
    print("Connected")
    stream_stub = stub.StreamChannel(iter([]))

if __name__ == "__main__":
    main()