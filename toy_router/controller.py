# This is a router we're going to use to emulate what we want to do in a P4 router


from p4runtime_lib.helper import P4InfoHelper

# Set up the connection to the switch
p4info_helper = P4InfoHelper('./build/basic.p4info')
sw = p4info_helper.switch_connection(name='s1', address='127.0.0.1:50051', device_id=0)

try:
    # Listen for digest messages
    while True:
        digests = sw.ReceiveDigestList()
        for digest in digests:
            sa_identifier = digest.data['sa_identifier']
            rekey_flag = digest.data['rekey_flag']
            print(f"Received digest: sa_identifier={sa_identifier}, rekey_flag={rekey_flag}")

            # Add a rule to the switch
            table_entry = p4info_helper.build_table_entry(
                table_name="MyIngress.my_table",
                match_fields={
                    "hdr.sectag.sa_identifier": sa_identifier
                },
                action_name="MyIngress.forward",
                action_params={
                    "port": 1  # Forward to port 1
                }
            )
            sw.WriteTableEntry(table_entry)
            print(f"Added rule: sa_identifier={sa_identifier} -> port 1")
finally:
    exit(0)



"""
// Digest data structure to send to the control plane
struct digest_data_t {
    bit<16> sa_identifier;
    bit<8>  rekey_flag;
}

control MyIngress {
    apply {
        // Check if the packet has a SecTag header
        if (hdr.sectag.isValid()) {
            // Send the sa_identifier and rekey_flag to the control plane
            digest_data_t digest_data;
            digest_data.sa_identifier = hdr.sectag.sa_identifier;
            digest_data.rekey_flag = hdr.sectag.rekey_flag;

            // Send a digest to the control plane
            digest(digest_data);
        }
    }
}
"""