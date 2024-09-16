#ifndef SWITCH_TYPEDEFS_P4
#define SWITCH_TYPEDEFS_P4

#include <core.p4>
#include <v1model.p4>

//v1model
#define PORT_ID_T_WIDTH 9
typedef bit<PORT_ID_T_WIDTH> portId_t;
typedef bit<8> shift_port_id_t; //portId_t that supports shifting: shifting is only supported by at most 8 bit amounts
typedef bit<16> mcast_grp_t;
typedef bit<32> clone_session_t;
typedef bit<48> timestamp_t;

//ethernet
typedef bit<16> etherType_t;
typedef bit<48> macAddr_t;

//arp
typedef bit<16> arp_opcode_t;

//ipv4, udp, tcp
typedef bit<32> ip4Addr_t;
typedef bit<8> protocol_t;
typedef bit<16> protocol_port_t;

//port leaf status
//Maximum number of ports a switch can have.
//  The bottleneck is the simple control plane implementation, which can be improved if necessary.
#define MAX_PORT_COUNT 9
typedef bit<MAX_PORT_COUNT> port_status_container_t;

//flow id
#define FLOW_SPECIFIER_T_WIDTH 32 //Must be at most 32 bits: the value is a CRC32 hash
typedef bit<FLOW_SPECIFIER_T_WIDTH> flow_specifier_t;

//path entry
typedef bit<3> path_storage_t;
#define PATH_INDEX_T_WIDTH 32 //Can't be any other number: registers only support 32 bit indexes at the moment
typedef bit<PATH_INDEX_T_WIDTH> path_index_t;

//shared between path entry and pnp packets
#define PATH_STRENGTH_T_WIDTH 4
typedef bit<PATH_STRENGTH_T_WIDTH> path_strength_t;

//pnp packets
typedef bit<8> pnp_subtype_t;

#endif //SWITCH_TYPEDEFS_P4
