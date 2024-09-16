#ifndef SWITCH_HEADERS_P4
#define SWITCH_HEADERS_P4

#include <core.p4>
#include <v1model.p4>
#include "switch_typedefs.p4"
#include "switch_globals.p4"
#include "switch_structs.p4"

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    etherType_t etherType;
}

//Common "base" of PNP packets: all PNP packets start with these fields.
//  Using both a custom ether type and a custom MAC makes sense, but is not really required:
//  in theory everything can still work if we only rely on one of these two.
const etherType_t ETHER_TYPE_PNP = 0x0809;
const macAddr_t MAC_PNP_INTERNAL = 0x070000000123;
header pnp_base_t {
    pnp_subtype_t subtype;
}
const pnp_subtype_t PNP_SUBTYPE_NONE = 0x00;

//Packet that tests whether the other side of the port is a host or a switch.
const pnp_subtype_t PNP_SUBTYPE_TEST = 0x01;
header pnp_test_t {
    bit<1> reply; //request=0; reply=1
    bit<7> padding; //reasoning: header bit width must be a multiple of 8
}

//Packet used by switches to request a path change for a flow.
const pnp_subtype_t PNP_SUBTYPE_REQUEST = 0x02;
header pnp_request_t {
    flow_id_t flow_id;
}

//Packet used by a leaf switch to start a learning process.
const pnp_subtype_t PNP_SUBTYPE_LEARN = 0x03;
header pnp_learn_t {
    flow_id_t flow_id;
    path_strength_t strength;
    bit<1> confirmation; //building=0; confirmation=1
    bit<1> singular_learn; //Whether singular entries can be learnt from this packet (yes=1; no=0)
    bit<2> padding; //reasoning: header bit width must be a multiple of 8
}

const etherType_t ETHER_TYPE_ARP = 0x0806;
header arp_t {
    bit<16> hwType;
    etherType_t protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    arp_opcode_t opcode;
    macAddr_t hwSrcAddr;
    ip4Addr_t protoSrcAddr;
    macAddr_t hwDstAddr;
    ip4Addr_t protoDstAddr;
}
const arp_opcode_t ARP_OPCODE_REQUEST = 1;
const arp_opcode_t ARP_OPCODE_REPLY = 2;

const etherType_t ETHER_TYPE_IPV4 = 0x0800;
header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    protocol_t protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

const protocol_t IPV4_PROTOCOL_TCP = 0x06;
header tcp_t {
    protocol_port_t srcPort;
    protocol_port_t dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

const protocol_t IPV4_PROTOCOL_UDP = 0x11;
header udp_t {
    protocol_port_t srcPort;
    protocol_port_t dstPort;
    bit<16> udplen;
    bit<16> udpchk;
}

struct headers {
    ethernet_t ethernet;
    pnp_base_t pnp_base;
    pnp_test_t pnp_test;
    pnp_request_t pnp_request;
    pnp_learn_t pnp_learn;
    arp_t arp; //unused
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.pnp_base);
        packet.emit(hdr.pnp_test);
        packet.emit(hdr.pnp_request);
        packet.emit(hdr.pnp_learn);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

#define INVALIDATE_ALL_HEADERS(HDR) \
        HDR.ethernet.setInvalid(); \
        HDR.pnp_base.setInvalid(); \
        HDR.pnp_test.setInvalid(); \
        HDR.pnp_request.setInvalid(); \
        HDR.pnp_learn.setInvalid(); \
        HDR.arp.setInvalid(); \
        HDR.ipv4.setInvalid(); \
        HDR.tcp.setInvalid(); \
        HDR.udp.setInvalid();

#endif //SWITCH_HEADERS_P4
