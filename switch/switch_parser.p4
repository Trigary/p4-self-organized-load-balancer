#ifndef SWITCH_PARSER_P4
#define SWITCH_PARSER_P4

#include <core.p4>
#include <v1model.p4>
#include "switch_typedefs.p4"
#include "switch_globals.p4"
#include "switch_headers.p4"
#include "switch_structs.p4"

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHER_TYPE_PNP: parse_pnp;
            ETHER_TYPE_ARP: parse_arp;
            ETHER_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_pnp {
        packet.extract(hdr.pnp_base);
        transition select(hdr.pnp_base.subtype) {
            PNP_SUBTYPE_TEST: parse_pnp_test;
            PNP_SUBTYPE_REQUEST: parse_pnp_request;
            PNP_SUBTYPE_LEARN: parse_pnp_learn;
            default: accept; //we accept it here, but drop during ingress processing (this way we can do logging)
        }
    }

    state parse_pnp_test {
        packet.extract(hdr.pnp_test);
        transition accept;
    }

    state parse_pnp_request {
        packet.extract(hdr.pnp_request);
        transition accept;
    }

    state parse_pnp_learn {
        packet.extract(hdr.pnp_learn);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPV4_PROTOCOL_TCP: parse_tcp;
            IPV4_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

#endif //SWITCH_PARSER_P4
