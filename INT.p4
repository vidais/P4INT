/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
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

struct metadata {
    /* empty */
}

header TCP_t{
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_number;
    bit<32> ack_number;
    bit<4> data_offset;
    bit<3> reserved_tcp;
    bit<9> control_flags;
    bit<16> window_size;
    bit<16> tcp_checksum;
    bit<16> urgent_ptr;
}

header INTshim_t{
    bit<4> type;
    bit<2> shim_zero;
    bit<2> r_flag;  //WHAT IS THIS??
    bit<8> len;
    bit<8> reserved;
    bit<6> dscp;
    bit<2> r_flag_two; //SAME QUESTION

}

header INT_t{
    bit<4> control_version;
    bit<1> discard;
    bit<1> max_hop_exceeded;
    bit<1> mtu_exceeded;
    bit<12> reserved;
    bit<5> hop_ml;
    bit<8> remaining_hop_count;
    bit<16> instruction;
    bit<32> node_id;
    bit<32> queue_occup;
}


struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    TCP_t        tcp;
    INT_t        p4int;
    INTshim_t    p4int_shim;

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