/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MACSEC = 0x88E5;
typedef bit<9>  egressSpec_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

/* MACSEC STUFF */
header sectag_t{
    bit<16>     system_identifier;
    bit<16>     sa_identifier;
    bit<8>      rekey_flag;
}

struct metadata {
    bit<9> egress_port;  // Store the egress port
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    sectag_t     sectag; /* MACSEC STUFF */
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

      state start {

        transition parse_ethernet;

    }

    state parse_ethernet {

        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_MACSEC: parse_sectag; /* MACSEC STUFF */
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            default: accept;
        }
    }
    /* MACSEC STUFF */
    state parse_sectag {
        packet.extract(hdr.sectag);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action forward(macAddr_t dstAddr, egressSpec_t port) {
       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        if (port == 0) {
            hdr.ethernet.srcAddr = 0x000000000002;
        } else if (port == 1) {
            hdr.ethernet.srcAddr = 0x000000000003;
        }

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    /* MACSEC STUFF */
    table sectag_table {
        key = {
            /* hdr.sectag.system_identifier: exact; */
            hdr.sectag.sa_identifier: exact;
            /* hdr.sectag.rekey_flag: exact; */
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
    }
    
    apply {
        if(hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        sectag_table.apply();  /* MACSEC STUFF */
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,              
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
		// parsed headers have to be added again into the packet
		packet.emit(hdr.ethernet);
		packet.emit(hdr.ipv4);
        packet.emit(hrd.sectag);
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
	MyParser(),
	MyVerifyChecksum(),
	MyIngress(),
	MyEgress(),
	MyComputeChecksum(),
	MyDeparser()
) main;


/*
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

*/