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
            srcAddr = digest.data['srcAddr']
            print(f"Received digest: sa_identifier={sa_identifier}, srcAddr={srcAddr}")

            # Add a rule to the switch
            # table_add MyIngress.sectag_table MyIngress.forward 11111 => 00:00:00:00:00:04 1
            table_entry = p4info_helper.build_table_entry(
                table_name="MyIngress.sectag_table",
                match_fields={
                    "hdr.sectag.sa_identifier": sa_identifier
                },
                action_name="MyIngress.forward",
                action_params={
                    "dstAddr": srcAddr,
                    "port": 1  # Forward to port 1
                }
            )
            sw.WriteTableEntry(table_entry)
            print(f"Added rule: sa_identifier={sa_identifier} -> {srcAddr} port 1")
finally:
    exit(0)
