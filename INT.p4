/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include <headers.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser IngressParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start { 
	transition parse_ethernet;
    }

    state parse_ethernet {
    	packet.extract(hdr.ethernet);
	transition select(hdr.ethernet.etherType){
		TYPE_IPV4: parse_ipv4;
		default: accept;
		}
	}
    state parse_ipv4{
    	packet.extract(hdr.ipv4);
	transition select(hdr.ipv4.dscp){
        0x17: parse_tcp;
        default: accept; 
        }
	}
    state parse_tcp{
        packet.extract(hdr.tcp);
        transition parse_int_shim;
    }

    state parse_int_shim{
        packet.extract(hdr.p4int_shim);
        transition select(hdr.p4int_shim.type){
            1: parse_p4int;
            default: accept;
        }
    }

    state parse_p4int{
        packet.extract(hdr.p4int);
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

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
    
	standard_metadata.egress_spec=port;
	hdr.ethernet.srcAddr=hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr=dstAddr;
	hdr.ipv4.ttl=hdr.ipv4.ttl - 1;

    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if(hdr.ipv4.isValid()){
        ipv4_lpm.apply();
	}
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

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
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
